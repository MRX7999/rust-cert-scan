//! Тесты обмена пробником ([`crate::probe_io`]).
//!
//! Сервер-заглушка воспроизводит байты фикстур `tls-probe`
//! (`crates/tls-probe/tests/fixtures/*.hex`, записаны со стенда
//! `openssl-basic`) на двух транспортах: `tokio::io::duplex` с
//! приостановленными часами tokio и локальный `TcpListener` на 127.0.0.1.
//! Внешних адресов нет.
//!
//! Разбор `.hex` — функция [`hex`] этого модуля: формат тривиален (пары
//! шестнадцатеричных цифр, строки-комментарии с `#`), а выносить его в
//! публичный API `tls-probe` ради тестов другого крейта не нужно.
//!
//! Тесты против стендов помечены `#[ignore]`; запуск описан в
//! атрибуте `#[ignore]` каждого такого теста и в `tests/stands/README.md`.

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tls_probe::{
    ContentType, Decoder, Event, HandshakeType, ParseError, ParseLimits, Sslv2ErrorCode,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::connector::{Conn, Connector, ConnectorConfig, Target};
use crate::dns::DnsCache;
use crate::probe_io::{
    EofKind, ProbeSession, ProbeTranscript, StopReason, TranscriptItem, Until, WriteFailure,
    send_and_collect,
};
use crate::timeouts::{Deadline, Timeouts};

/// Байты фикстуры: строки-комментарии и пробелы пропускаются.
fn hex(text: &str) -> Vec<u8> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::split_whitespace)
        .map(|pair| u8::from_str_radix(pair, 16).unwrap())
        .collect()
}

macro_rules! fixture {
    ($name:literal) => {
        hex(include_str!(concat!(
            "../../tls-probe/tests/fixtures/",
            $name,
            ".hex"
        )))
    };
}

fn tls12_hello() -> Vec<u8> {
    fixture!("tls12-clienthello-openssl-basic")
}
fn tls12_reply() -> Vec<u8> {
    fixture!("tls12-serverhello-openssl-basic")
}
fn tls13_hello() -> Vec<u8> {
    fixture!("tls13-clienthello-openssl-basic")
}
fn tls13_reply() -> Vec<u8> {
    // Записанная фикстура кончается на ChangeCipherSpec (133 байта, без
    // зашифрованных записей). Чтобы условие «первое зашифрованное
    // содержимое» было проверяемо, к ней дописана синтетическая запись
    // application_data на 32 байта: так выглядит первая зашифрованная
    // запись после CCS. Записанный шифртекст есть в обмене с HRR.
    let mut bytes = fixture!("tls13-serverhello-openssl-basic");
    bytes.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x20]);
    bytes.extend_from_slice(&[0xEE; 32]);
    bytes
}
fn hrr_first_hello() -> Vec<u8> {
    fixture!("tls13-clienthello-openssl-basic-no-key-share")
}
fn hrr_second_hello() -> Vec<u8> {
    fixture!("tls13-clienthello-openssl-basic-after-hrr")
}
/// Полный поток сервера в обмене с HRR: HRR, CCS, второй ServerHello,
/// зашифрованная запись.
fn hrr_full_reply() -> Vec<u8> {
    fixture!("tls13-serverhello-openssl-basic-after-hrr")
}
fn alert_hello() -> Vec<u8> {
    fixture!("tls12-clienthello-openssl-basic-rsa-only")
}
fn alert_reply() -> Vec<u8> {
    fixture!("tls12-alert-openssl-basic-no-shared-cipher")
}
fn fragmented_hello() -> Vec<u8> {
    fixture!("tls12-clienthello-openssl-basic-max-send-frag")
}
fn fragmented_reply() -> Vec<u8> {
    fixture!("tls12-serverhello-openssl-basic-max-send-frag")
}
fn dhe_rsa_hello() -> Vec<u8> {
    fixture!("tls12-clienthello-openssl-basic-dhe-rsa")
}
fn dhe_rsa_reply() -> Vec<u8> {
    fixture!("tls12-serverhello-openssl-basic-dhe-rsa")
}

/// Смещение в [`hrr_full_reply`], с которого начинается ответ на второй
/// ClientHello (`second_request_offset` в `.meta.toml`): до него — HRR и
/// CCS.
const HRR_SPLIT: usize = 99;

/// Запись handshake с одним сообщением ServerHelloDone.
const SERVER_HELLO_DONE_RECORD: [u8; 9] = [0x16, 0x03, 0x03, 0x00, 0x04, 0x0E, 0x00, 0x00, 0x00];

/// Как заглушка отдаёт ответ: порциями по `chunk` байтов с паузой `gap`
/// (нулевая пауза — уступка планировщику).
#[derive(Debug, Clone, Copy)]
struct Delivery {
    chunk: usize,
    gap: Duration,
}

const WHOLE: Delivery = Delivery {
    chunk: usize::MAX,
    gap: Duration::ZERO,
};
/// По одному байту; на приостановленных часах пауза ничего не стоит.
const BYTEWISE: Delivery = Delivery {
    chunk: 1,
    gap: Duration::from_millis(1),
};
const PAUSED: Delivery = Delivery {
    chunk: 97,
    gap: Duration::from_millis(20),
};
/// Варианты для реальных сокетов: без долгих ожиданий.
const TCP_BYTEWISE: Delivery = Delivery {
    chunk: 1,
    gap: Duration::ZERO,
};
const TCP_PAUSED: Delivery = Delivery {
    chunk: 97,
    gap: Duration::from_millis(2),
};

const MEMORY_DELIVERIES: [Delivery; 3] = [WHOLE, BYTEWISE, PAUSED];
const TCP_DELIVERIES: [Delivery; 3] = [WHOLE, TCP_BYTEWISE, TCP_PAUSED];

async fn deliver<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    delivery: Delivery,
) -> io::Result<()> {
    for chunk in bytes.chunks(delivery.chunk.max(1)) {
        writer.write_all(chunk).await?;
        writer.flush().await?;
        if delivery.gap.is_zero() {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(delivery.gap).await;
        }
    }
    Ok(())
}

/// Шаг сценария заглушки. После последнего шага заглушка закрывает
/// соединение.
#[derive(Debug, Clone)]
enum Step {
    /// Прочитать ровно столько байтов (пробник клиента).
    Expect(usize),
    /// Отправить байты.
    Send(Vec<u8>, Delivery),
    /// Держать соединение открытым, пока клиент его не закроет.
    Hold,
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, steps: Vec<Step>) {
    for step in steps {
        match step {
            Step::Expect(len) => {
                let mut buf = vec![0; len];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
            }
            Step::Send(bytes, delivery) => {
                // Клиент мог остановиться по условию и закрыть соединение.
                if deliver(&mut stream, &bytes, delivery).await.is_err() {
                    return;
                }
            }
            Step::Hold => {
                let mut sink = [0_u8; 64];
                while matches!(stream.read(&mut sink).await, Ok(count) if count > 0) {}
                return;
            }
        }
    }
}

fn reply_steps(hello: &[u8], reply: &[u8], delivery: Delivery) -> Vec<Step> {
    vec![
        Step::Expect(hello.len()),
        Step::Send(reply.to_vec(), delivery),
        Step::Hold,
    ]
}

fn hrr_steps(delivery: Delivery) -> Vec<Step> {
    let full = hrr_full_reply();
    vec![
        Step::Expect(hrr_first_hello().len()),
        Step::Send(full[..HRR_SPLIT].to_vec(), delivery),
        Step::Expect(hrr_second_hello().len()),
        Step::Send(full[HRR_SPLIT..].to_vec(), delivery),
        Step::Hold,
    ]
}

/// Таймауты тестов на приостановленных часах.
fn paused_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
        read: Duration::from_secs(1),
        write: Duration::from_secs(1),
        exchange: Duration::from_secs(10),
    }
}

/// Таймауты тестов на реальных сокетах: с запасом, тест их не ждёт.
fn tcp_timeouts() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(5),
        handshake: Duration::from_secs(5),
        read: Duration::from_secs(5),
        write: Duration::from_secs(5),
        exchange: Duration::from_secs(20),
    }
}

fn duplex_pair(steps: Vec<Step>) -> (DuplexStream, JoinHandle<()>) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    (client, tokio::spawn(serve(server, steps)))
}

fn memory_session(steps: Vec<Step>) -> (ProbeSession<DuplexStream>, JoinHandle<()>) {
    memory_session_with(steps, paused_timeouts(), ParseLimits::default())
}

fn memory_session_with(
    steps: Vec<Step>,
    timeouts: Timeouts,
    limits: ParseLimits,
) -> (ProbeSession<DuplexStream>, JoinHandle<()>) {
    let (client, server) = duplex_pair(steps);
    (ProbeSession::new(client, timeouts, limits), server)
}

async fn connect(port: u16, timeouts: Timeouts) -> Conn {
    let config = ConnectorConfig {
        timeouts,
        ..ConnectorConfig::default()
    };
    // Цель — IP-литерал: системный резолвер не вызывается.
    let connector = Connector::new(Arc::new(DnsCache::system()), config);
    let scope = connector.stats().child();
    connector
        .connect(&Target::new("127.0.0.1", port), &scope)
        .await
        .unwrap()
}

async fn tcp_session(
    steps: Vec<Step>,
    timeouts: Timeouts,
) -> (ProbeSession<TcpStream>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        serve(stream, steps).await;
    });
    let conn = connect(port, timeouts).await;
    (
        ProbeSession::from_conn(conn, ParseLimits::default()),
        server,
    )
}

/// Handshake-сообщения фикстуры, полученные декодером напрямую, без `net`.
fn decode_handshakes(bytes: &[u8]) -> Vec<(HandshakeType, Vec<u8>)> {
    let mut decoder = Decoder::default();
    let mut input = bytes;
    let mut messages = Vec::new();
    loop {
        match decoder.feed(&mut input).unwrap() {
            Event::NeedMore => break,
            Event::Handshake(message) => messages.push((message.msg_type, message.body.to_vec())),
            _ => {}
        }
    }
    messages
}

fn handshakes_of(transcript: &ProbeTranscript) -> Vec<(HandshakeType, Vec<u8>)> {
    transcript
        .handshake_messages()
        .map(|message| (message.msg_type, message.body().to_vec()))
        .collect()
}

type Session<S> = ProbeSession<S>;

/// TLS 1.2: чтение до ServerHelloDone; сообщения совпадают с тем, что даёт
/// декодер на тех же байтах.
async fn check_tls12<S>(session: &mut Session<S>, hello: &[u8], reply: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let transcript = session
        .send_and_collect(hello, Until::ServerHelloDone)
        .await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    assert_eq!(transcript.write_failure, None);
    assert!(!transcript.awaiting_second_hello);
    assert_eq!(transcript.bytes_sent, hello.len());
    assert!(transcript.bytes_received > 0);
    assert!(transcript.bytes_received <= reply.len());
    assert_eq!(transcript.alerts().count(), 0);

    let mut expected = decode_handshakes(reply);
    let done = expected
        .iter()
        .position(|(msg_type, _)| *msg_type == HandshakeType::SERVER_HELLO_DONE)
        .unwrap();
    expected.truncate(done + 1);
    assert_eq!(handshakes_of(&transcript), expected);

    let types: Vec<HandshakeType> = transcript
        .handshake_messages()
        .map(|message| message.msg_type)
        .collect();
    assert_eq!(
        types,
        [
            HandshakeType::SERVER_HELLO,
            HandshakeType::CERTIFICATE,
            HandshakeType::SERVER_KEY_EXCHANGE,
            HandshakeType::SERVER_HELLO_DONE,
        ]
    );
    for message in transcript.handshake_messages() {
        assert_eq!(message.raw().len(), message.body().len() + 4);
        assert_eq!(message.raw().first(), Some(&message.msg_type.0));
    }
    assert!(transcript.handshake(HandshakeType::CERTIFICATE).is_some());
    assert!(transcript.handshake(HandshakeType::FINISHED).is_none());
}

/// TLS 1.3: чтение до первой зашифрованной записи.
async fn check_tls13<S>(session: &mut Session<S>, hello: &[u8], reply: &[u8])
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let transcript = session.send_and_collect(hello, Until::FirstEncrypted).await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    assert!(!transcript.awaiting_second_hello);
    assert_eq!(transcript.bytes_sent, hello.len());

    let expected = decode_handshakes(reply);
    assert_eq!(handshakes_of(&transcript).first(), expected.first());
    let first_item = transcript.items.first().unwrap();
    assert!(first_item.is_handshake(HandshakeType::SERVER_HELLO));

    let ciphertexts = transcript
        .items
        .iter()
        .filter(|item| item.is_ciphertext())
        .count();
    assert_eq!(ciphertexts, 1, "чтение остановлено на первой записи");
    let Some(TranscriptItem::Record(record)) = transcript.items.last() else {
        panic!(
            "последний элемент — не запись: {:?}",
            transcript.items.last()
        );
    };
    assert!(record.ciphertext);
    assert_eq!(record.content_type, ContentType::APPLICATION_DATA);
    assert!(!record.payload.is_empty());
}

/// Полный обмен с HRR: два раунда на одном соединении, один декодер.
async fn check_hrr<S>(session: &mut Session<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first_hello = hrr_first_hello();
    let second_hello = hrr_second_hello();
    let full = hrr_full_reply();
    let expected = decode_handshakes(&full);
    assert_eq!(expected.len(), 2, "в потоке HRR и второй ServerHello");

    let first = session
        .send_and_collect(&first_hello, Until::ServerHello)
        .await;
    assert!(first.condition_met(), "{}", first.stop);
    assert!(first.awaiting_second_hello, "первый server_hello — это HRR");
    assert_eq!(handshakes_of(&first), expected[..1]);
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.bytes_sent, first_hello.len());

    let second = session
        .send_and_collect(&second_hello, Until::FirstEncrypted)
        .await;
    assert!(second.condition_met(), "{}", second.stop);
    assert!(!second.awaiting_second_hello);
    assert_eq!(second.bytes_sent, second_hello.len());
    assert_eq!(handshakes_of(&second), expected[1..]);
    // CCS пришёл сразу за HRR и не потерян между раундами; режим Opaque он
    // не включил, поэтому второй ServerHello разобран открытым текстом.
    let [
        TranscriptItem::ChangeCipherSpec,
        TranscriptItem::Handshake(server_hello),
        TranscriptItem::Record(record),
    ] = second.items.as_slice()
    else {
        panic!("неожиданный состав второго раунда: {:?}", second.items);
    };
    assert_eq!(server_hello.msg_type, HandshakeType::SERVER_HELLO);
    // D-14: после второго ServerHello CCS нет, шифртекст приходит событием
    // ApplicationData (версии записи у него нет) и распознан как шифртекст.
    assert!(record.ciphertext);
    assert_eq!(record.version, None);
    assert_eq!(record.content_type, ContentType::APPLICATION_DATA);

    assert_eq!(session.bytes_sent(), first_hello.len() + second_hello.len());
    assert!(session.bytes_received() <= full.len());
    assert_eq!(
        first.bytes_received + second.bytes_received,
        session.bytes_received()
    );
}

/// Fatal alert — результат обмена, а не ошибка.
async fn check_alert<S>(session: &mut Session<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let transcript = session
        .send_and_collect(&alert_hello(), Until::ServerFlight)
        .await;
    assert_eq!(transcript.stop, StopReason::FatalAlert);
    assert!(!transcript.stop.is_terminal());
    assert!(!transcript.condition_met());
    assert_eq!(transcript.items.len(), 1);
    assert_eq!(transcript.alerts().count(), 1);
    let alert = transcript.fatal_alert().unwrap();
    assert!(alert.is_fatal());
    assert_eq!(transcript.handshake_messages().count(), 0);
    assert_eq!(transcript.bytes_received, alert_reply().len());
}

#[test]
fn fixtures_have_the_expected_shape() {
    let full = hrr_full_reply();
    let hrr_only = fixture!("tls13-hrr-openssl-basic");
    assert_eq!(hrr_only.len(), HRR_SPLIT);
    assert!(full.starts_with(&hrr_only));
    assert_eq!(alert_reply().len(), 7);
    for reply in [tls12_reply(), fragmented_reply(), dhe_rsa_reply()] {
        assert_eq!(decode_handshakes(&reply).len(), 4);
    }
}

// ---------------------------------------------------------------------------
// Сценарии на фикстурах: in-memory транспорт, приостановленные часы.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn memory_tls12_until_server_hello_done() {
    let cases = [
        (tls12_hello(), tls12_reply()),
        (fragmented_hello(), fragmented_reply()),
        (dhe_rsa_hello(), dhe_rsa_reply()),
    ];
    for delivery in MEMORY_DELIVERIES {
        for (hello, reply) in &cases {
            let (mut session, server) = memory_session(reply_steps(hello, reply, delivery));
            check_tls12(&mut session, hello, reply).await;
            session.close().await;
            server.await.unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn memory_tls13_until_first_encrypted() {
    let (hello, reply) = (tls13_hello(), tls13_reply());
    for delivery in MEMORY_DELIVERIES {
        let (mut session, server) = memory_session(reply_steps(&hello, &reply, delivery));
        check_tls13(&mut session, &hello, &reply).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn memory_hrr_exchange_with_second_client_hello() {
    for delivery in MEMORY_DELIVERIES {
        let (mut session, server) = memory_session(hrr_steps(delivery));
        check_hrr(&mut session).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn memory_fatal_alert_is_a_result() {
    for delivery in MEMORY_DELIVERIES {
        let steps = reply_steps(&alert_hello(), &alert_reply(), delivery);
        let (mut session, server) = memory_session(steps);
        check_alert(&mut session).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn until_alert_is_met_by_the_alert() {
    let steps = reply_steps(&alert_hello(), &alert_reply(), WHOLE);
    let (mut session, _server) = memory_session(steps);
    let transcript = session.send_and_collect(&alert_hello(), Until::Alert).await;
    assert_eq!(transcript.stop, StopReason::ConditionMet);
    assert!(transcript.fatal_alert().is_some());
}

#[tokio::test(start_paused = true)]
async fn until_server_hello_stops_at_the_first_message_and_reading_continues() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let (mut session, _server) = memory_session(reply_steps(&hello, &reply, WHOLE));
    let expected = decode_handshakes(&reply);

    let first = session.send_and_collect(&hello, Until::ServerHello).await;
    assert!(first.condition_met(), "{}", first.stop);
    assert_eq!(handshakes_of(&first), expected[..1]);
    assert!(!first.awaiting_second_hello);

    // Раунд с пустым пробником ничего не отправляет и дочитывает ответ:
    // остаток буфера и состояние декодера сохранены.
    let rest = session.send_and_collect(&[], Until::ServerHelloDone).await;
    assert!(rest.condition_met(), "{}", rest.stop);
    assert_eq!(rest.bytes_sent, 0);
    assert_eq!(handshakes_of(&rest), expected[1..]);
    assert_eq!(session.bytes_sent(), hello.len());
    assert_eq!(session.bytes_received(), reply.len());
    assert_eq!(session.first_bytes(), &reply[..16]);
}

#[tokio::test(start_paused = true)]
async fn until_server_flight_covers_both_protocol_generations() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let (mut session, _server) = memory_session(reply_steps(&hello, &reply, WHOLE));
    let transcript = session.send_and_collect(&hello, Until::ServerFlight).await;
    assert!(transcript.condition_met());
    assert!(
        transcript
            .items
            .last()
            .unwrap()
            .is_handshake(HandshakeType::SERVER_HELLO_DONE)
    );

    let (hello, reply) = (tls13_hello(), tls13_reply());
    let (mut session, _server) = memory_session(reply_steps(&hello, &reply, WHOLE));
    let transcript = session.send_and_collect(&hello, Until::ServerFlight).await;
    assert!(transcript.condition_met());
    assert!(transcript.items.last().unwrap().is_ciphertext());
}

#[tokio::test(start_paused = true)]
async fn until_predicate_sees_every_item_in_order() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let (mut session, _server) = memory_session(reply_steps(&hello, &reply, BYTEWISE));
    let mut seen = 0;
    let until = Until::predicate(move |item| {
        seen += 1;
        seen == 2 && item.is_handshake(HandshakeType::CERTIFICATE)
    });
    assert_eq!(format!("{until:?}"), "Predicate(..)");

    let transcript = session.send_and_collect(&hello, until).await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    assert_eq!(transcript.items.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn one_shot_exchange_closes_the_connection_without_close_notify() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let (hello_len, reply_bytes) = (hello.len(), reply.clone());
    let server = tokio::spawn(async move {
        let mut seen = vec![0; hello_len];
        server.read_exact(&mut seen).await.unwrap();
        server.write_all(&reply_bytes).await.unwrap();
        // Всё, что клиент пришлёт до закрытия, и сам факт закрытия.
        let mut trailing = Vec::new();
        server.read_to_end(&mut trailing).await.unwrap();
        (seen, trailing)
    });

    let peer = (Ipv4Addr::LOCALHOST, 4433).into();
    let conn = Conn::from_stream(client, peer, None, paused_timeouts());
    let transcript = send_and_collect(conn, &hello, Until::ServerFlight).await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    assert_eq!(transcript.handshake_messages().count(), 4);

    let (seen, trailing) = server.await.unwrap();
    assert_eq!(seen, hello, "пробник доставлен без изменений");
    assert!(trailing.is_empty(), "после пробника клиент ничего не шлёт");
}

// ---------------------------------------------------------------------------
// Причины остановки: in-memory транспорт, приостановленные часы.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn eof_before_first_byte() {
    let hello = tls12_hello();
    let (mut session, server) = memory_session(vec![Step::Expect(hello.len())]);

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(transcript.stop, StopReason::Eof(EofKind::BeforeFirstByte));
    assert_eq!(transcript.stop.label(), "eof_before_first_byte");
    assert!(transcript.items.is_empty());
    assert_eq!(transcript.bytes_sent, hello.len());
    assert_eq!(transcript.bytes_received, 0);
    server.await.unwrap();

    // Причина окончательная: следующий раунд ввода-вывода не выполняет.
    let again = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(again.stop, StopReason::Eof(EofKind::BeforeFirstByte));
    assert_eq!(again.bytes_sent, 0);
    assert_eq!(session.bytes_sent(), hello.len());
}

#[tokio::test(start_paused = true)]
async fn eof_in_the_middle_of_a_message() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    // Обрыв посреди первой записи и обрыв после полной записи ServerHello
    // с одним лишним байтом следующей.
    let server_hello_record_len =
        5 + usize::from(u16::from_be_bytes(reply[3..5].try_into().unwrap()));
    for cut in [1, 3, 20, server_hello_record_len + 1] {
        let steps = vec![
            Step::Expect(hello.len()),
            Step::Send(reply[..cut].to_vec(), WHOLE),
        ];
        let (mut session, _server) = memory_session(steps);
        let transcript = session
            .send_and_collect(&hello, Until::ServerHelloDone)
            .await;
        assert_eq!(
            transcript.stop,
            StopReason::Eof(EofKind::MidMessage),
            "обрыв после {cut} байт"
        );
        assert_eq!(transcript.bytes_received, cut);
    }
}

#[tokio::test(start_paused = true)]
async fn eof_on_a_message_boundary() {
    let hello = tls12_hello();
    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(SERVER_HELLO_DONE_RECORD.to_vec(), WHOLE),
    ];
    let (mut session, _server) = memory_session(steps);
    let transcript = session
        .send_and_collect(&hello, Until::predicate(|_| false))
        .await;
    assert_eq!(transcript.stop, StopReason::Eof(EofKind::AtMessageBoundary));
    assert_eq!(transcript.stop.label(), "eof");
    assert_eq!(transcript.items.len(), 1, "прочитанное до EOF сохранено");
}

#[tokio::test(start_paused = true)]
async fn handshake_timeout_when_the_server_is_silent() {
    let hello = tls12_hello();
    let (mut session, _server) = memory_session(vec![Step::Expect(hello.len()), Step::Hold]);

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(transcript.stop, StopReason::HandshakeTimeout);
    assert_eq!(transcript.duration, paused_timeouts().handshake);
    assert!(transcript.items.is_empty());
    assert!(!transcript.stop.is_terminal());
}

#[tokio::test(start_paused = true)]
async fn read_timeout_between_portions() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(reply[..3].to_vec(), WHOLE),
        Step::Hold,
    ];
    let (mut session, _server) = memory_session(steps);

    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    assert_eq!(transcript.stop, StopReason::ReadTimeout);
    // Первый байт пришёл сразу, дальше — таймаут read, а не handshake.
    assert_eq!(transcript.duration, paused_timeouts().read);
    assert_eq!(transcript.bytes_received, 3);
}

/// Начало бесконечного «капельного» ответа: запись handshake на 16384
/// байта с сообщением Certificate на 65280 байт; дальше — нули.
fn drip_stream(len: usize) -> Vec<u8> {
    let mut bytes = vec![0x16, 0x03, 0x03, 0x40, 0x00, 0x0B, 0x00, 0xFF, 0x00];
    bytes.resize(len, 0);
    bytes
}

#[tokio::test(start_paused = true)]
async fn overall_deadline_stops_a_dripping_server() {
    let hello = tls12_hello();
    let drip = Delivery {
        chunk: 1,
        gap: Duration::from_millis(100),
    };
    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(drip_stream(2000), drip),
        Step::Hold,
    ];
    let (mut session, _server) = memory_session(steps);

    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    // Каждый байт укладывается в таймаут read (1 с), но общий дедлайн
    // (10 с) обрывает обмен.
    assert_eq!(transcript.stop, StopReason::Deadline);
    assert_eq!(transcript.stop.label(), "deadline");
    assert!(transcript.duration >= Duration::from_secs(10));
    assert!(transcript.duration < Duration::from_millis(10_200));
    assert!(transcript.bytes_received >= 90);
    assert!(transcript.bytes_received <= 110);
    assert!(transcript.stop.is_terminal());
}

#[tokio::test(start_paused = true)]
async fn external_deadline_caps_every_read() {
    let hello = tls12_hello();
    let timeouts = Timeouts {
        handshake: Duration::from_secs(5),
        ..paused_timeouts()
    };
    let (mut session, _server) = memory_session_with(
        vec![Step::Expect(hello.len()), Step::Hold],
        timeouts,
        ParseLimits::default(),
    );
    let check_deadline = Deadline::after(Instant::now(), Duration::from_secs(3));
    session.set_deadline(check_deadline);
    assert_eq!(session.deadline(), check_deadline);
    // Более поздний дедлайн действующий не ослабляет.
    session.set_deadline(Deadline::after(Instant::now(), Duration::from_secs(60)));
    assert_eq!(session.deadline(), check_deadline);

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    // Таймаут handshake — 5 с, но чтение ограничено остатком до дедлайна.
    assert_eq!(transcript.stop, StopReason::Deadline);
    assert_eq!(transcript.duration, Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn expired_deadline_sends_nothing() {
    let hello = tls12_hello();
    let (mut session, _server) = memory_session(vec![Step::Hold]);
    session.set_deadline(Deadline::at(Instant::now()));

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(transcript.stop, StopReason::Deadline);
    assert_eq!(transcript.bytes_sent, 0);
    assert_eq!(transcript.duration, Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn non_tls_reply_is_reported_with_its_first_bytes() {
    let hello = tls12_hello();
    let replies: [&[u8]; 2] = [
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        b"220 mail.example.test ESMTP ready\r\n",
    ];
    for reply in replies {
        // Целиком: первые 16 байт ответа.
        let (mut session, _server) = memory_session(reply_steps(&hello, reply, WHOLE));
        let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
        assert_eq!(
            transcript.stop,
            StopReason::NotTls {
                first_bytes: reply[..16].to_vec()
            }
        );
        assert_eq!(transcript.stop.label(), "not_tls");
        assert!(transcript.items.is_empty());
        assert!(transcript.stop.is_terminal());

        // По байту: неизвестный тип записи виден уже по первому байту,
        // поэтому в причине остановки может быть всего один байт.
        let (mut session, _server) = memory_session(reply_steps(&hello, reply, BYTEWISE));
        let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
        let StopReason::NotTls { first_bytes } = &transcript.stop else {
            panic!("ожидался NotTls, получено {}", transcript.stop);
        };
        assert!(!first_bytes.is_empty());
        assert!(reply.starts_with(first_bytes));
    }
}

#[tokio::test(start_paused = true)]
async fn total_bytes_limit_stops_the_exchange() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let limits = ParseLimits {
        max_total_bytes: 64,
        ..ParseLimits::default()
    };
    let (mut session, _server) = memory_session_with(
        reply_steps(&hello, &reply, WHOLE),
        paused_timeouts(),
        limits,
    );

    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    let StopReason::LimitExceeded(error) = &transcript.stop else {
        panic!("ожидался LimitExceeded, получено {}", transcript.stop);
    };
    assert!(matches!(
        error,
        ParseError::LimitExceeded {
            limit: "max_total_bytes",
            max: 64,
            ..
        }
    ));
    assert_eq!(transcript.stop.label(), "limit");
    assert!(transcript.stop.is_terminal());
    assert!(transcript.items.is_empty(), "тело за лимитом не копируется");
}

#[tokio::test(start_paused = true)]
async fn flood_of_empty_records_hits_the_limit() {
    let hello = tls12_hello();
    let flood: Vec<u8> = [0x17, 0x03, 0x03, 0x00, 0x00].repeat(200);
    let (mut session, _server) = memory_session(reply_steps(&hello, &flood, WHOLE));

    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    let StopReason::LimitExceeded(error) = &transcript.stop else {
        panic!("ожидался LimitExceeded, получено {}", transcript.stop);
    };
    assert!(matches!(
        error,
        ParseError::LimitExceeded {
            limit: "max_empty_records",
            ..
        }
    ));
    // Пустые записи до ServerHello — не шифртекст, условие не выполнено.
    assert!(transcript.items.len() <= 16);
    assert!(transcript.items.iter().all(|item| !item.is_ciphertext()));
}

#[tokio::test(start_paused = true)]
async fn write_error_when_the_server_is_gone() {
    let hello = tls12_hello();
    let (client, server) = tokio::io::duplex(64 * 1024);
    drop(server);
    let mut session = ProbeSession::new(client, paused_timeouts(), ParseLimits::default());

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    let failure = WriteFailure {
        kind: io::ErrorKind::BrokenPipe,
        written: 0,
        total: hello.len(),
    };
    assert_eq!(transcript.stop, StopReason::WriteFailed(failure));
    assert_eq!(transcript.stop.label(), "write");
    assert_eq!(transcript.write_failure, Some(failure));
    assert_eq!(transcript.bytes_sent, 0);
    assert!(transcript.stop.is_terminal());
}

#[tokio::test(start_paused = true)]
async fn reply_sent_before_a_write_error_is_not_lost() {
    let hello = tls12_hello();
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    // Сервер отвечает alert'ом, не читая пробник, и закрывает соединение.
    let reply = alert_reply();
    tokio::spawn(async move {
        server.write_all(&reply).await.unwrap();
    })
    .await
    .unwrap();
    let mut session = ProbeSession::new(client, paused_timeouts(), ParseLimits::default());

    let transcript = session.send_and_collect(&hello, Until::ServerFlight).await;
    assert_eq!(transcript.stop, StopReason::FatalAlert);
    assert!(transcript.fatal_alert().is_some());
    let failure = transcript.write_failure.unwrap();
    assert_eq!(failure.kind, io::ErrorKind::BrokenPipe);
    assert_eq!(failure.total, hello.len());
}

#[tokio::test(start_paused = true)]
async fn partial_write_times_out_with_the_number_of_bytes_written() {
    let hello = tls12_hello();
    assert!(hello.len() > 16);
    // Транспорт принимает 16 байт; сервер ничего не читает.
    let (client, _server) = tokio::io::duplex(16);
    let mut session = ProbeSession::new(client, paused_timeouts(), ParseLimits::default());

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    let failure = WriteFailure {
        kind: io::ErrorKind::TimedOut,
        written: 16,
        total: hello.len(),
    };
    assert_eq!(transcript.stop, StopReason::WriteFailed(failure));
    assert_eq!(transcript.write_failure, Some(failure));
    assert_eq!(transcript.bytes_sent, 16);
    assert_eq!(transcript.duration, paused_timeouts().write);
    assert!(transcript.stop.to_string().contains("16 из"));
}

// ---------------------------------------------------------------------------
// SSLv2.
// ---------------------------------------------------------------------------

/// Байты вместо настоящего SSLv2 CLIENT-HELLO: заглушка их только считает.
const SSLV2_HELLO: [u8; 5] = [0x80, 0x03, 0x01, 0x00, 0x02];

fn sslv2_session(reply: &[u8], delivery: Delivery) -> ProbeSession<DuplexStream> {
    let (client, _server) = duplex_pair(vec![
        Step::Expect(SSLV2_HELLO.len()),
        Step::Send(reply.to_vec(), delivery),
    ]);
    ProbeSession::sslv2(client, paused_timeouts(), ParseLimits::default())
}

#[tokio::test(start_paused = true)]
async fn sslv2_error_stops_like_a_fatal_alert() {
    // Запись из трёх байтов: ERROR, код NO-CIPHER.
    let reply = [0x80, 0x03, 0x00, 0x00, 0x01];
    for delivery in [WHOLE, BYTEWISE] {
        let mut session = sslv2_session(&reply, delivery);
        let transcript = session
            .send_and_collect(&SSLV2_HELLO, Until::ServerHello)
            .await;
        assert_eq!(transcript.stop, StopReason::FatalAlert);
        assert_eq!(
            transcript.items,
            [TranscriptItem::Sslv2Error(Sslv2ErrorCode::NO_CIPHER)]
        );
    }
}

#[tokio::test(start_paused = true)]
async fn sslv2_server_hello_is_copied_into_the_transcript() {
    // SERVER-HELLO: hit = 0, тип сертификата X.509, версия 0x0002,
    // сертификат 2 байта, один cipher kind, CONNECTION-ID 16 байт.
    let mut message = vec![
        0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x10,
    ];
    message.extend_from_slice(&[0x30, 0x00]);
    message.extend_from_slice(&[0x07, 0x00, 0xC0]);
    message.extend_from_slice(&[0xAB; 16]);
    let mut reply = vec![0x80, u8::try_from(message.len()).unwrap()];
    reply.extend_from_slice(&message);

    for delivery in [WHOLE, BYTEWISE] {
        let mut session = sslv2_session(&reply, delivery);
        let transcript = session
            .send_and_collect(&SSLV2_HELLO, Until::ServerHello)
            .await;
        assert!(transcript.condition_met(), "{}", transcript.stop);
        let [TranscriptItem::Sslv2ServerHello(hello)] = transcript.items.as_slice() else {
            panic!("неожиданный состав: {:?}", transcript.items);
        };
        assert!(!hello.session_id_hit);
        assert_eq!(hello.version.0, 0x0002);
        assert_eq!(hello.certificate, [0x30, 0x00]);
        assert_eq!(hello.cipher_specs, [0x07, 0x00, 0xC0]);
        assert_eq!(hello.connection_id, [0xAB; 16]);
    }
}

#[tokio::test(start_paused = true)]
async fn sslv2_session_falls_back_to_tls_when_the_server_replies_with_tls() {
    for delivery in [WHOLE, BYTEWISE] {
        // Сервер без SSLv2 отвечает TLS alert'ом.
        let mut session = sslv2_session(&alert_reply(), delivery);
        let transcript = session
            .send_and_collect(&SSLV2_HELLO, Until::ServerHello)
            .await;
        assert_eq!(transcript.stop, StopReason::FatalAlert);
        assert!(transcript.fatal_alert().is_some());

        // Либо полным ответом TLS 1.2.
        let mut session = sslv2_session(&tls12_reply(), delivery);
        let transcript = session
            .send_and_collect(&SSLV2_HELLO, Until::ServerHelloDone)
            .await;
        assert!(transcript.condition_met(), "{}", transcript.stop);
        assert_eq!(
            handshakes_of(&transcript),
            decode_handshakes(&tls12_reply())
        );
    }
}

#[tokio::test(start_paused = true)]
async fn sslv2_eof_in_the_middle_of_a_record() {
    let mut session = sslv2_session(&[0x80, 0x03, 0x00], WHOLE);
    let transcript = session
        .send_and_collect(&SSLV2_HELLO, Until::ServerHello)
        .await;
    assert_eq!(transcript.stop, StopReason::Eof(EofKind::MidMessage));
}

#[test]
fn stop_reason_labels_and_messages() {
    let parse_error = ParseError::InvalidValue {
        position: 5,
        what: "тест",
    };
    let reasons = [
        (StopReason::ConditionMet, "condition"),
        (StopReason::FatalAlert, "fatal_alert"),
        (StopReason::Eof(EofKind::MidMessage), "eof_mid_message"),
        (
            StopReason::Reset {
                kind: io::ErrorKind::ConnectionReset,
            },
            "reset",
        ),
        (StopReason::HandshakeTimeout, "handshake_timeout"),
        (StopReason::ReadTimeout, "read_timeout"),
        (StopReason::Parse(parse_error), "parse"),
        (
            StopReason::Io {
                kind: io::ErrorKind::Other,
            },
            "io",
        ),
    ];
    for (reason, label) in reasons {
        assert_eq!(reason.label(), label);
        assert!(!reason.to_string().is_empty());
    }
    let not_tls = StopReason::NotTls {
        first_bytes: b"HTTP".to_vec(),
    };
    assert!(not_tls.to_string().ends_with("48 54 54 50"), "{not_tls}");
    assert!(
        StopReason::Parse(parse_error)
            .to_string()
            .contains("смещении 5")
    );
}

// ---------------------------------------------------------------------------
// Реальные сокеты на 127.0.0.1.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_tls12_until_server_hello_done() {
    let cases = [
        (tls12_hello(), tls12_reply()),
        (fragmented_hello(), fragmented_reply()),
        (dhe_rsa_hello(), dhe_rsa_reply()),
    ];
    for delivery in TCP_DELIVERIES {
        for (hello, reply) in &cases {
            let steps = reply_steps(hello, reply, delivery);
            let (mut session, server) = tcp_session(steps, tcp_timeouts()).await;
            check_tls12(&mut session, hello, reply).await;
            session.close().await;
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn tcp_tls13_until_first_encrypted() {
    let (hello, reply) = (tls13_hello(), tls13_reply());
    for delivery in TCP_DELIVERIES {
        let steps = reply_steps(&hello, &reply, delivery);
        let (mut session, server) = tcp_session(steps, tcp_timeouts()).await;
        check_tls13(&mut session, &hello, &reply).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_hrr_exchange_with_second_client_hello() {
    for delivery in TCP_DELIVERIES {
        let (mut session, server) = tcp_session(hrr_steps(delivery), tcp_timeouts()).await;
        check_hrr(&mut session).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_fatal_alert_is_a_result() {
    for delivery in TCP_DELIVERIES {
        let steps = reply_steps(&alert_hello(), &alert_reply(), delivery);
        let (mut session, server) = tcp_session(steps, tcp_timeouts()).await;
        check_alert(&mut session).await;
        session.close().await;
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_eof_before_first_byte_and_in_the_middle_of_a_message() {
    let (hello, reply) = (tls12_hello(), tls12_reply());

    let steps = vec![Step::Expect(hello.len())];
    let (mut session, server) = tcp_session(steps, tcp_timeouts()).await;
    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(transcript.stop, StopReason::Eof(EofKind::BeforeFirstByte));
    server.await.unwrap();

    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(reply[..20].to_vec(), WHOLE),
    ];
    let (mut session, server) = tcp_session(steps, tcp_timeouts()).await;
    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    assert_eq!(transcript.stop, StopReason::Eof(EofKind::MidMessage));
    assert_eq!(transcript.bytes_received, 20);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_reset_by_the_server() {
    let hello = tls12_hello();
    let hello_len = hello.len();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.unwrap();
        let mut seen = vec![0; hello_len];
        stream.read_exact(&mut seen).await.unwrap();
        // SO_LINGER 0: закрытие отправляет RST вместо FIN.
        stream.set_zero_linger().unwrap();
        drop(stream);
    });
    let conn = connect(port, tcp_timeouts()).await;
    let mut session = ProbeSession::from_conn(conn, ParseLimits::default());

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(
        transcript.stop,
        StopReason::Reset {
            kind: io::ErrorKind::ConnectionReset
        }
    );
    assert_eq!(transcript.stop.label(), "reset");
    assert_eq!(transcript.bytes_sent, hello.len());
    assert!(transcript.stop.is_terminal());
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_handshake_and_read_timeouts() {
    let (hello, reply) = (tls12_hello(), tls12_reply());
    let timeouts = Timeouts {
        handshake: Duration::from_millis(150),
        read: Duration::from_millis(150),
        ..tcp_timeouts()
    };

    let steps = vec![Step::Expect(hello.len()), Step::Hold];
    let (mut session, server) = tcp_session(steps, timeouts).await;
    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    assert_eq!(transcript.stop, StopReason::HandshakeTimeout);
    assert!(transcript.duration >= Duration::from_millis(150));
    session.close().await;
    server.await.unwrap();

    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(reply[..3].to_vec(), WHOLE),
        Step::Hold,
    ];
    let (mut session, server) = tcp_session(steps, timeouts).await;
    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    assert_eq!(transcript.stop, StopReason::ReadTimeout);
    assert_eq!(transcript.bytes_received, 3);
    session.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_overall_deadline_stops_a_dripping_server() {
    let hello = tls12_hello();
    let timeouts = Timeouts {
        exchange: Duration::from_millis(300),
        ..tcp_timeouts()
    };
    let drip = Delivery {
        chunk: 1,
        gap: Duration::from_millis(10),
    };
    let steps = vec![
        Step::Expect(hello.len()),
        Step::Send(drip_stream(2000), drip),
        Step::Hold,
    ];
    let (mut session, server) = tcp_session(steps, timeouts).await;

    let transcript = session
        .send_and_collect(&hello, Until::ServerHelloDone)
        .await;
    assert_eq!(transcript.stop, StopReason::Deadline);
    assert!(transcript.bytes_received > 0);
    assert!(transcript.duration < Duration::from_secs(3));
    session.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_non_tls_reply() {
    let hello = tls12_hello();
    let reply = b"HTTP/1.1 400 Bad Request\r\n\r\n";
    let (mut session, server) =
        tcp_session(reply_steps(&hello, reply, WHOLE), tcp_timeouts()).await;

    let transcript = session.send_and_collect(&hello, Until::ServerHello).await;
    let StopReason::NotTls { first_bytes } = &transcript.stop else {
        panic!("ожидался NotTls, получено {}", transcript.stop);
    };
    assert!(first_bytes.starts_with(b"HT"));
    assert!(reply.starts_with(first_bytes));
    session.close().await;
    server.await.unwrap();
}

// ---------------------------------------------------------------------------
// Стенды openssl-basic (tests/stands/README.md).
// ---------------------------------------------------------------------------

/// Порт стенда по умолчанию: ECDSA, TLS 1.2 и TLS 1.3.
const STAND_BASIC: u16 = 4433;
/// Стенд с фрагментацией handshake-сообщений (`STAND_MAX_SEND_FRAG`).
const STAND_FRAGMENTED: u16 = 4434;
/// Стенд с RSA-сертификатом и шифром DHE-RSA.
const STAND_DHE_RSA: u16 = 4435;

async fn stand_session(port: u16) -> ProbeSession<TcpStream> {
    let conn = connect(port, Timeouts::default()).await;
    ProbeSession::from_conn(conn, ParseLimits::default())
}

async fn check_stand_tls12(port: u16, hello: &[u8]) -> ProbeTranscript {
    let mut session = stand_session(port).await;
    let transcript = session
        .send_and_collect(hello, Until::ServerHelloDone)
        .await;
    session.close().await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    let types: Vec<HandshakeType> = transcript
        .handshake_messages()
        .map(|message| message.msg_type)
        .collect();
    assert_eq!(
        types,
        [
            HandshakeType::SERVER_HELLO,
            HandshakeType::CERTIFICATE,
            HandshakeType::SERVER_KEY_EXCHANGE,
            HandshakeType::SERVER_HELLO_DONE,
        ]
    );
    transcript
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_tls12_until_server_hello_done() {
    let transcript = check_stand_tls12(STAND_BASIC, &tls12_hello()).await;
    assert_eq!(transcript.bytes_sent, tls12_hello().len());
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_fragmented_certificate() {
    let transcript = check_stand_tls12(STAND_FRAGMENTED, &fragmented_hello()).await;
    let certificate = transcript.handshake(HandshakeType::CERTIFICATE).unwrap();
    assert!(!certificate.body().is_empty());
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_dhe_rsa() {
    check_stand_tls12(STAND_DHE_RSA, &dhe_rsa_hello()).await;
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_tls13_until_first_encrypted() {
    let mut session = stand_session(STAND_BASIC).await;
    let transcript = session
        .send_and_collect(&tls13_hello(), Until::FirstEncrypted)
        .await;
    session.close().await;
    assert!(transcript.condition_met(), "{}", transcript.stop);
    let first_item = transcript.items.first().unwrap();
    assert!(first_item.is_handshake(HandshakeType::SERVER_HELLO));
    assert!(transcript.items.last().unwrap().is_ciphertext());
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_hrr_exchange() {
    let mut session = stand_session(STAND_BASIC).await;
    let first = session
        .send_and_collect(&hrr_first_hello(), Until::ServerHello)
        .await;
    assert!(first.condition_met(), "{}", first.stop);
    assert!(first.awaiting_second_hello);

    let second = session
        .send_and_collect(&hrr_second_hello(), Until::FirstEncrypted)
        .await;
    session.close().await;
    assert!(second.condition_met(), "{}", second.stop);
    assert!(!second.awaiting_second_hello);
    assert!(second.handshake(HandshakeType::SERVER_HELLO).is_some());
    assert!(second.items.last().unwrap().is_ciphertext());
}

#[tokio::test]
#[ignore = "нужны стенды openssl-basic на 127.0.0.1:4433, 4434, 4435 (tests/stands/README.md); запуск: cargo test -p net -- --ignored"]
async fn stand_no_shared_cipher_alert() {
    let mut session = stand_session(STAND_BASIC).await;
    let transcript = session
        .send_and_collect(&alert_hello(), Until::ServerFlight)
        .await;
    session.close().await;
    assert_eq!(transcript.stop, StopReason::FatalAlert);
    assert!(transcript.fatal_alert().is_some());
}
