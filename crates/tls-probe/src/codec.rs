//! Примитивы кодека wire-формата TLS: [`Reader`] и [`Writer`].
//!
//! Все многобайтовые числа — в сетевом порядке (big-endian). Вектор TLS —
//! это префикс длины в 1, 2 или 3 байта и следующее за ним тело.
//!
//! [`Reader`] работает поверх `&[u8]`, ничего не копирует и не аллоцирует:
//! все возвращаемые срезы и вложенные читатели заимствуют исходный буфер.
//! Длина из данных используется только для сравнения с остатком, память по
//! ней не выделяется. Неудачное чтение не сдвигает позицию читателя.
//!
//! [`Writer`] пишет в расширяемый буфер [`BytesMut`]. Вектор можно записать
//! целиком (`put_vec_*`) либо через замыкание с отложенным заполнением
//! префикса (`nested_*`). Если тело не помещается в префикс, возвращается
//! [`EncodeError::LengthOverflow`], а буфер откатывается к состоянию до
//! начала записи вектора.
//!
//! Модуль не выполняет I/O, не содержит `unsafe`, не паникует и не
//! индексирует срезы без проверки.

use bytes::BytesMut;

use crate::error::{EncodeError, ParseError};

/// Размер префикса длины вектора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefix {
    U8,
    U16,
    U24,
}

impl Prefix {
    /// Число байтов префикса.
    const fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
        }
    }

    /// Наибольшая длина тела, представимая префиксом.
    const fn max(self) -> u32 {
        match self {
            Self::U8 => 0xFF,
            Self::U16 => 0xFFFF,
            Self::U24 => 0x00FF_FFFF,
        }
    }
}

/// Последовательный читатель поверх среза байтов.
///
/// Позиция отсчитывается от начала исходного буфера и сохраняется во
/// вложенных читателях, поэтому позиция в [`ParseError`] всегда абсолютная.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    /// Ещё не прочитанные байты.
    data: &'a [u8],
    /// Смещение `data` от начала исходного буфера.
    position: usize,
}

impl<'a> Reader<'a> {
    /// Читатель с начала буфера.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Смещение следующего непрочитанного байта от начала исходного буфера.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Число непрочитанных байтов.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Истина, если непрочитанных байтов нет.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Непрочитанные байты без сдвига позиции.
    #[must_use]
    pub fn as_slice(&self) -> &'a [u8] {
        self.data
    }

    /// Забирает все непрочитанные байты; после вызова читатель пуст.
    pub fn rest(&mut self) -> &'a [u8] {
        let data = self.data;
        self.position = self.position.saturating_add(data.len());
        self.data = &[];
        data
    }

    /// Читает один байт.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn u8(&mut self) -> Result<u8, ParseError> {
        let [value] = self.array()?;
        Ok(value)
    }

    /// Читает 16-битное число.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn u16(&mut self) -> Result<u16, ParseError> {
        self.array().map(u16::from_be_bytes)
    }

    /// Читает 24-битное число в младшие биты `u32`.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn u24(&mut self) -> Result<u32, ParseError> {
        let [high, middle, low] = self.array()?;
        Ok(u32::from_be_bytes([0, high, middle, low]))
    }

    /// Читает 32-битное число.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn u32(&mut self) -> Result<u32, ParseError> {
        self.array().map(u32::from_be_bytes)
    }

    /// Читает массив фиксированной длины.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let Some((head, tail)) = self.data.split_first_chunk::<N>() else {
            return Err(self.eof(N));
        };
        self.data = tail;
        self.position = self.position.saturating_add(N);
        Ok(*head)
    }

    /// Читает срез заданной длины.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        let Some((head, tail)) = self.data.split_at_checked(len) else {
            return Err(self.eof(len));
        };
        self.data = tail;
        self.position = self.position.saturating_add(len);
        Ok(head)
    }

    /// Пропускает заданное число байтов.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn skip(&mut self, len: usize) -> Result<(), ParseError> {
        self.take(len).map(|_| ())
    }

    /// Отделяет вложенный читатель на заданное число байтов.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если данных не хватает.
    pub fn sub(&mut self, len: usize) -> Result<Self, ParseError> {
        let position = self.position;
        let data = self.take(len)?;
        Ok(Self { data, position })
    }

    /// Читает вектор с однобайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn vec_u8(&mut self) -> Result<&'a [u8], ParseError> {
        self.prefixed(Prefix::U8).map(|inner| inner.data)
    }

    /// Читает вектор с двухбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn vec_u16(&mut self) -> Result<&'a [u8], ParseError> {
        self.prefixed(Prefix::U16).map(|inner| inner.data)
    }

    /// Читает вектор с трёхбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn vec_u24(&mut self) -> Result<&'a [u8], ParseError> {
        self.prefixed(Prefix::U24).map(|inner| inner.data)
    }

    /// Читает вектор с однобайтовым префиксом как вложенный читатель.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn sub_u8(&mut self) -> Result<Self, ParseError> {
        self.prefixed(Prefix::U8)
    }

    /// Читает вектор с двухбайтовым префиксом как вложенный читатель.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn sub_u16(&mut self) -> Result<Self, ParseError> {
        self.prefixed(Prefix::U16)
    }

    /// Читает вектор с трёхбайтовым префиксом как вложенный читатель.
    ///
    /// # Errors
    ///
    /// [`ParseError::UnexpectedEof`], если не хватает байтов префикса или
    /// длина вектора больше остатка.
    pub fn sub_u24(&mut self) -> Result<Self, ParseError> {
        self.prefixed(Prefix::U24)
    }

    /// Проверяет, что все данные прочитаны.
    ///
    /// # Errors
    ///
    /// [`ParseError::TrailingBytes`], если остались непрочитанные байты.
    pub fn finish(self) -> Result<(), ParseError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(ParseError::TrailingBytes {
                position: self.position,
                remaining: self.data.len(),
            })
        }
    }

    /// Читает префикс длины и тело вектора; при ошибке позиция не меняется.
    fn prefixed(&mut self, prefix: Prefix) -> Result<Self, ParseError> {
        let mut probe = self.clone();
        let len = match prefix {
            Prefix::U8 => usize::from(probe.u8()?),
            Prefix::U16 => usize::from(probe.u16()?),
            Prefix::U24 => usize::try_from(probe.u24()?).unwrap_or(usize::MAX),
        };
        let inner = probe.sub(len)?;
        *self = probe;
        Ok(inner)
    }

    fn eof(&self, needed: usize) -> ParseError {
        ParseError::UnexpectedEof {
            position: self.position,
            needed,
            available: self.data.len(),
        }
    }
}

/// Последовательный писатель в расширяемый буфер.
#[derive(Debug, Default)]
pub struct Writer {
    buf: BytesMut,
}

impl Writer {
    /// Писатель с пустым буфером.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Писатель с буфером заданной начальной ёмкости.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    /// Писатель, дописывающий в переданный буфер (для переиспользования).
    #[must_use]
    pub fn from_buffer(buf: BytesMut) -> Self {
        Self { buf }
    }

    /// Число записанных байтов, включая содержимое переданного буфера.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Истина, если буфер пуст.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Записанные байты.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Возвращает буфер с записанными байтами.
    #[must_use]
    pub fn into_inner(self) -> BytesMut {
        self.buf
    }

    /// Пишет один байт.
    pub fn put_u8(&mut self, value: u8) {
        self.buf.extend_from_slice(&[value]);
    }

    /// Пишет 16-битное число.
    pub fn put_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Пишет 24-битное число из младших битов `u32`.
    ///
    /// # Errors
    ///
    /// [`EncodeError::ValueOverflow`], если значение не помещается в 24 бита.
    pub fn put_u24(&mut self, value: u32) -> Result<(), EncodeError> {
        let [overflow, high, middle, low] = value.to_be_bytes();
        if overflow != 0 {
            return Err(EncodeError::ValueOverflow {
                max: Prefix::U24.max(),
                actual: value,
            });
        }
        self.buf.extend_from_slice(&[high, middle, low]);
        Ok(())
    }

    /// Пишет 32-битное число.
    pub fn put_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Пишет байты как есть, без префикса длины.
    pub fn put_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Пишет вектор с однобайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если длина больше 255.
    pub fn put_vec_u8(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        self.put_prefixed(Prefix::U8, data)
    }

    /// Пишет вектор с двухбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если длина больше 65535.
    pub fn put_vec_u16(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        self.put_prefixed(Prefix::U16, data)
    }

    /// Пишет вектор с трёхбайтовым префиксом длины.
    ///
    /// # Errors
    ///
    /// [`EncodeError::LengthOverflow`], если длина больше 16777215.
    pub fn put_vec_u24(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        self.put_prefixed(Prefix::U24, data)
    }

    /// Пишет вектор с однобайтовым префиксом; тело записывает замыкание,
    /// длина подставляется после него.
    ///
    /// # Errors
    ///
    /// Ошибка замыкания либо [`EncodeError::LengthOverflow`], если тело
    /// длиннее 255 байтов. В обоих случаях буфер откатывается.
    pub fn nested_u8<F>(&mut self, fill: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.nested(Prefix::U8, fill)
    }

    /// Пишет вектор с двухбайтовым префиксом; тело записывает замыкание,
    /// длина подставляется после него.
    ///
    /// # Errors
    ///
    /// Ошибка замыкания либо [`EncodeError::LengthOverflow`], если тело
    /// длиннее 65535 байтов. В обоих случаях буфер откатывается.
    pub fn nested_u16<F>(&mut self, fill: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.nested(Prefix::U16, fill)
    }

    /// Пишет вектор с трёхбайтовым префиксом; тело записывает замыкание,
    /// длина подставляется после него.
    ///
    /// # Errors
    ///
    /// Ошибка замыкания либо [`EncodeError::LengthOverflow`], если тело
    /// длиннее 16777215 байтов. В обоих случаях буфер откатывается.
    pub fn nested_u24<F>(&mut self, fill: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        self.nested(Prefix::U24, fill)
    }

    fn put_prefixed(&mut self, prefix: Prefix, data: &[u8]) -> Result<(), EncodeError> {
        let length = length_bytes(prefix, data.len())?;
        self.buf.extend(prefix_bytes(prefix, &length));
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn nested<F>(&mut self, prefix: Prefix, fill: F) -> Result<(), EncodeError>
    where
        F: FnOnce(&mut Self) -> Result<(), EncodeError>,
    {
        let start = self.buf.len();
        self.buf.extend(std::iter::repeat_n(0_u8, prefix.width()));
        let body_start = self.buf.len();

        if let Err(error) = fill(self) {
            self.buf.truncate(start);
            return Err(error);
        }

        let body_len = self.buf.len().saturating_sub(body_start);
        let length = match length_bytes(prefix, body_len) {
            Ok(length) => length,
            Err(error) => {
                self.buf.truncate(start);
                return Err(error);
            }
        };
        for (slot, byte) in self
            .buf
            .iter_mut()
            .skip(start)
            .zip(prefix_bytes(prefix, &length))
        {
            *slot = byte;
        }
        Ok(())
    }
}

/// Длина тела как четыре байта big-endian; ошибка, если она не помещается
/// в префикс.
fn length_bytes(prefix: Prefix, len: usize) -> Result<[u8; 4], EncodeError> {
    u32::try_from(len)
        .ok()
        .filter(|value| *value <= prefix.max())
        .map(u32::to_be_bytes)
        .ok_or(EncodeError::LengthOverflow {
            prefix_bytes: prefix.width(),
            max: prefix.max(),
            actual: len,
        })
}

/// Младшие байты длины по ширине префикса.
fn prefix_bytes(prefix: Prefix, length: &[u8; 4]) -> impl Iterator<Item = u8> + '_ {
    length
        .iter()
        .skip(length.len().saturating_sub(prefix.width()))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eof(position: usize, needed: usize, available: usize) -> ParseError {
        ParseError::UnexpectedEof {
            position,
            needed,
            available,
        }
    }

    #[test]
    fn reads_every_primitive() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xAA, 0xBB, 0xC1, 0xC2,
            0xC3,
        ];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), 15);
        assert!(!reader.is_empty());

        assert_eq!(reader.u8(), Ok(0x01));
        assert_eq!(reader.u16(), Ok(0x0203));
        assert_eq!(reader.u24(), Ok(0x0004_0506));
        assert_eq!(reader.u32(), Ok(0x0708_090A));
        assert_eq!(reader.position(), 10);
        assert_eq!(reader.take(2), Ok(&[0xAA, 0xBB][..]));
        assert_eq!(reader.array::<3>(), Ok([0xC1, 0xC2, 0xC3]));
        assert_eq!(reader.position(), 15);
        assert!(reader.is_empty());
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn empty_input() {
        let mut reader = Reader::new(&[]);
        assert!(reader.is_empty());
        assert_eq!(reader.remaining(), 0);
        assert_eq!(reader.u8(), Err(eof(0, 1, 0)));
        assert_eq!(reader.u16(), Err(eof(0, 2, 0)));
        assert_eq!(reader.u24(), Err(eof(0, 3, 0)));
        assert_eq!(reader.u32(), Err(eof(0, 4, 0)));
        assert_eq!(reader.array::<5>(), Err(eof(0, 5, 0)));
        assert_eq!(reader.take(1), Err(eof(0, 1, 0)));
        assert_eq!(reader.skip(1), Err(eof(0, 1, 0)));
        assert_eq!(reader.vec_u8(), Err(eof(0, 1, 0)));
        assert_eq!(reader.vec_u16(), Err(eof(0, 2, 0)));
        assert_eq!(reader.vec_u24(), Err(eof(0, 3, 0)));
        assert!(reader.sub_u8().is_err());
        assert!(reader.sub_u16().is_err());
        assert!(reader.sub_u24().is_err());
        assert!(reader.sub(1).is_err());

        assert_eq!(reader.take(0), Ok(&[][..]));
        assert_eq!(reader.array::<0>(), Ok([]));
        assert!(reader.rest().is_empty());
        assert!(reader.as_slice().is_empty());
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn truncated_primitives_report_needed_and_available() {
        let data = [0x11, 0x22, 0x33];

        let mut reader = Reader::new(&data);
        assert_eq!(reader.u32(), Err(eof(0, 4, 3)));
        assert_eq!(reader.take(4), Err(eof(0, 4, 3)));
        assert_eq!(reader.array::<4>(), Err(eof(0, 4, 3)));
        assert_eq!(reader.skip(4), Err(eof(0, 4, 3)));
        assert_eq!(reader.position(), 0, "ошибка не сдвигает позицию");
        assert_eq!(reader.remaining(), 3);

        assert_eq!(reader.u8(), Ok(0x11));
        assert_eq!(reader.u24(), Err(eof(1, 3, 2)));
        assert_eq!(reader.u8(), Ok(0x22));
        assert_eq!(reader.u16(), Err(eof(2, 2, 1)));
        assert_eq!(reader.u8(), Ok(0x33));
        assert_eq!(reader.u8(), Err(eof(3, 1, 0)));
    }

    #[test]
    fn reads_length_prefixed_vectors() {
        let data = [
            0x02, 0xAA, 0xBB, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x02, 0x09, 0x08, 0x00,
            0x7F,
        ];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u8(), Ok(&[0xAA, 0xBB][..]));
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.vec_u16(), Ok(&[0x01, 0x02, 0x03][..]));
        assert_eq!(reader.position(), 8);
        assert_eq!(reader.vec_u24(), Ok(&[0x09, 0x08][..]));
        assert_eq!(reader.position(), 13);
        assert_eq!(reader.vec_u8(), Ok(&[][..]), "пустой вектор");
        assert_eq!(reader.as_slice(), &[0x7F_u8][..]);
        assert_eq!(reader.rest(), &[0x7F_u8][..]);
        assert_eq!(reader.position(), 15);
        assert_eq!(reader.finish(), Ok(()));
    }

    #[test]
    fn vector_longer_than_remaining() {
        let data = [0x05, 0x01, 0x02];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u8(), Err(eof(1, 5, 2)));
        assert_eq!(reader.position(), 0, "префикс не потреблён при ошибке");
        assert_eq!(reader.remaining(), 3);
        assert!(reader.sub_u8().is_err());
        assert_eq!(reader.position(), 0);

        let data = [0xFF, 0xFF, 0x01];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u16(), Err(eof(2, 0xFFFF, 1)));
        assert_eq!(reader.position(), 0);

        let data = [0xFF, 0xFF, 0xFF, 0x01, 0x02];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u24(), Err(eof(3, 0x00FF_FFFF, 2)));
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), 5);
    }

    #[test]
    fn truncated_length_prefix() {
        let data = [0x00_u8];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u16(), Err(eof(0, 2, 1)));
        assert_eq!(reader.vec_u24(), Err(eof(0, 3, 1)));
        assert_eq!(reader.remaining(), 1);

        let data = [0x00, 0x00];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.vec_u24(), Err(eof(0, 3, 2)));
        assert_eq!(reader.vec_u16(), Ok(&[][..]));
    }

    #[test]
    fn nested_vectors_keep_absolute_positions() {
        let data = [0x00, 0x05, 0x02, 0xAA, 0xBB, 0x01, 0xCC, 0xFF];
        let mut outer = Reader::new(&data);
        let mut inner = outer.sub_u16().unwrap();
        assert_eq!(outer.position(), 7);
        assert_eq!(inner.position(), 2);
        assert_eq!(inner.remaining(), 5);

        assert_eq!(inner.vec_u8(), Ok(&[0xAA, 0xBB][..]));
        assert_eq!(inner.position(), 5);
        let mut innermost = inner.sub_u8().unwrap();
        assert_eq!(innermost.position(), 6);
        assert_eq!(innermost.u8(), Ok(0xCC));
        assert_eq!(innermost.finish(), Ok(()));
        assert_eq!(inner.finish(), Ok(()));

        assert_eq!(outer.u8(), Ok(0xFF));
        assert_eq!(outer.finish(), Ok(()));
    }

    #[test]
    fn nested_reader_cannot_read_past_its_bounds() {
        // Внутренний вектор заявляет 5 байтов, во внешнем их только 2, хотя
        // в исходном буфере после внешнего вектора данные ещё есть.
        let data = [0x00, 0x03, 0x05, 0xAA, 0xBB, 0x01, 0x02, 0x03];
        let mut outer = Reader::new(&data);
        let mut inner = outer.sub_u16().unwrap();
        assert_eq!(inner.vec_u8(), Err(eof(3, 5, 2)));
        assert_eq!(inner.position(), 2);
        assert_eq!(inner.u32(), Err(eof(2, 4, 3)));
        assert_eq!(outer.remaining(), 3);

        let mut reader = Reader::new(&data);
        let mut sub = reader.sub(3).unwrap();
        assert_eq!(sub.position(), 0);
        assert_eq!(sub.u24(), Ok(0x0000_0305));
        assert_eq!(sub.u8(), Err(eof(3, 1, 0)));
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.sub(6).unwrap_err(), eof(3, 6, 5));
        let sub_u24 = Reader::new(&[0x00, 0x00, 0x01, 0x42]).sub_u24().unwrap();
        assert_eq!(sub_u24.as_slice(), &[0x42_u8][..]);
    }

    #[test]
    fn trailing_bytes() {
        let data = [0x01, 0x02, 0x03];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.u8(), Ok(0x01));
        assert_eq!(
            reader.clone().finish(),
            Err(ParseError::TrailingBytes {
                position: 1,
                remaining: 2
            })
        );
        assert_eq!(reader.skip(2), Ok(()));
        assert_eq!(reader.finish(), Ok(()));

        let mut outer = Reader::new(&data);
        let inner = outer.sub(2).unwrap();
        assert_eq!(
            inner.finish(),
            Err(ParseError::TrailingBytes {
                position: 0,
                remaining: 2
            })
        );
    }

    #[test]
    fn writes_every_primitive() {
        let mut writer = Writer::new();
        assert!(writer.is_empty());
        assert_eq!(writer.len(), 0);

        writer.put_u8(0x01);
        writer.put_u16(0x0203);
        assert_eq!(writer.put_u24(0x0004_0506), Ok(()));
        writer.put_u32(0x0708_090A);
        writer.put_slice(&[0xAA, 0xBB]);
        writer.put_slice(&[]);
        assert_eq!(
            writer.as_slice(),
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0xAA, 0xBB
            ][..]
        );
        assert_eq!(writer.len(), 12);
        assert!(!writer.is_empty());
        assert_eq!(writer.put_u24(0x00FF_FFFF), Ok(()));
        assert_eq!(writer.len(), 15);
    }

    #[test]
    fn u24_value_overflow() {
        let mut writer = Writer::new();
        writer.put_u8(0x55);
        assert_eq!(
            writer.put_u24(0x0100_0000),
            Err(EncodeError::ValueOverflow {
                max: 0x00FF_FFFF,
                actual: 0x0100_0000
            })
        );
        assert_eq!(writer.as_slice(), &[0x55_u8][..], "буфер не изменён");
    }

    #[test]
    fn writes_length_prefixed_vectors() {
        let mut writer = Writer::new();
        assert_eq!(writer.put_vec_u8(&[0xAA, 0xBB]), Ok(()));
        assert_eq!(writer.put_vec_u16(&[0x01, 0x02, 0x03]), Ok(()));
        assert_eq!(writer.put_vec_u24(&[0x09, 0x08]), Ok(()));
        assert_eq!(writer.put_vec_u8(&[]), Ok(()));
        assert_eq!(
            writer.as_slice(),
            &[
                0x02, 0xAA, 0xBB, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x02, 0x09, 0x08, 0x00
            ][..]
        );
    }

    #[test]
    fn vector_length_prefix_overflow() {
        let mut writer = Writer::new();
        writer.put_u8(0x77);

        assert_eq!(writer.put_vec_u8(&[0xAB; 255]), Ok(()));
        assert_eq!(writer.len(), 257);
        assert_eq!(
            writer.put_vec_u8(&[0xAB; 256]),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                max: 0xFF,
                actual: 256
            })
        );
        assert_eq!(writer.len(), 257, "буфер не изменён при ошибке");

        let exact = vec![0xCD_u8; 0xFFFF];
        assert_eq!(writer.put_vec_u16(&exact), Ok(()));
        let too_long = vec![0xCD_u8; 0x1_0000];
        assert_eq!(
            writer.put_vec_u16(&too_long),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000
            })
        );

        let huge = vec![0_u8; 0x0100_0000];
        let mut writer = Writer::new();
        assert_eq!(
            writer.put_vec_u24(&huge),
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 3,
                max: 0x00FF_FFFF,
                actual: 0x0100_0000
            })
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn nested_vectors_fill_length_afterwards() {
        let mut writer = Writer::new();
        writer.put_u8(0x16);
        let result = writer.nested_u16(|outer| {
            outer.nested_u8(|inner| {
                inner.put_slice(&[0xAA, 0xBB]);
                Ok(())
            })?;
            outer.put_vec_u8(&[0xCC_u8])?;
            outer.nested_u24(|inner| {
                inner.put_u16(0x0102);
                Ok(())
            })?;
            outer.nested_u8(|_| Ok(()))
        });
        assert_eq!(result, Ok(()));
        writer.put_u8(0xFF);

        assert_eq!(
            writer.as_slice(),
            &[
                0x16, 0x00, 0x0B, 0x02, 0xAA, 0xBB, 0x01, 0xCC, 0x00, 0x00, 0x02, 0x01, 0x02, 0x00,
                0xFF
            ][..]
        );
    }

    #[test]
    fn nested_overflow_rolls_back() {
        let mut writer = Writer::new();
        writer.put_u16(0xBEEF);

        let result = writer.nested_u8(|inner| {
            inner.put_slice(&[0x11; 256]);
            Ok(())
        });
        assert_eq!(
            result,
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 1,
                max: 0xFF,
                actual: 256
            })
        );
        assert_eq!(writer.as_slice(), &[0xBE, 0xEF][..]);

        let result = writer.nested_u16(|inner| {
            inner.put_slice(&vec![0x22_u8; 0x1_0000]);
            Ok(())
        });
        assert_eq!(
            result,
            Err(EncodeError::LengthOverflow {
                prefix_bytes: 2,
                max: 0xFFFF,
                actual: 0x1_0000
            })
        );
        assert_eq!(writer.as_slice(), &[0xBE, 0xEF][..]);

        // Ошибка из замыкания откатывает весь внешний вектор.
        let result = writer.nested_u24(|outer| {
            outer.put_u8(0x01);
            outer.nested_u8(|inner| {
                inner.put_u8(0x02);
                inner.put_u24(0xFFFF_FFFF)
            })
        });
        assert_eq!(
            result,
            Err(EncodeError::ValueOverflow {
                max: 0x00FF_FFFF,
                actual: 0xFFFF_FFFF
            })
        );
        assert_eq!(writer.as_slice(), &[0xBE, 0xEF][..]);

        // Ровно на границе префикса запись проходит.
        let result = writer.nested_u8(|inner| {
            inner.put_slice(&[0x33; 255]);
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(writer.len(), 2 + 1 + 255);
    }

    #[test]
    fn writer_reuses_buffer() {
        let mut buffer = BytesMut::with_capacity(64);
        buffer.extend_from_slice(&[0xDE, 0xAD]);
        let mut writer = Writer::from_buffer(buffer);
        assert_eq!(writer.len(), 2);
        writer.put_u8(0x01);
        let buffer = writer.into_inner();
        assert_eq!(&buffer[..], &[0xDE, 0xAD, 0x01][..]);

        let writer = Writer::with_capacity(128);
        assert!(writer.is_empty());
        assert!(writer.into_inner().capacity() >= 128);
    }

    #[test]
    fn round_trip_writer_to_reader() {
        let payload: Vec<u8> = (0..=255).collect();
        let mut writer = Writer::new();
        writer.put_u8(0xA5);
        writer.put_u16(0xC02F);
        writer.put_u24(0x0001_0203).unwrap();
        writer.put_u32(0xDEAD_BEEF);
        writer.put_slice(&[0x10, 0x20, 0x30, 0x40]);
        writer.put_vec_u8(&payload[..255]).unwrap();
        writer.put_vec_u16(&payload).unwrap();
        writer.put_vec_u24(&payload).unwrap();
        writer
            .nested_u16(|list| {
                for item in [&payload[..3], &payload[..0], &payload[..200]] {
                    list.put_vec_u8(item)?;
                }
                Ok(())
            })
            .unwrap();

        let bytes = writer.into_inner();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8(), Ok(0xA5));
        assert_eq!(reader.u16(), Ok(0xC02F));
        assert_eq!(reader.u24(), Ok(0x0001_0203));
        assert_eq!(reader.u32(), Ok(0xDEAD_BEEF));
        assert_eq!(reader.array::<4>(), Ok([0x10, 0x20, 0x30, 0x40]));
        assert_eq!(reader.vec_u8(), Ok(&payload[..255]));
        assert_eq!(reader.vec_u16(), Ok(&payload[..]));
        assert_eq!(reader.vec_u24(), Ok(&payload[..]));

        let mut list = reader.sub_u16().unwrap();
        assert_eq!(list.vec_u8(), Ok(&payload[..3]));
        assert_eq!(list.vec_u8(), Ok(&payload[..0]));
        assert_eq!(list.vec_u8(), Ok(&payload[..200]));
        assert_eq!(list.finish(), Ok(()));
        assert_eq!(reader.finish(), Ok(()));
    }
}
