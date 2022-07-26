use crate::error::KSError;
use serialport;
use std::io::ErrorKind;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const BAUD_RATE: u32 = 115_200;

pub struct SerialManager<'a> {
    port_name: &'a str,
    timeout_ms: u64,
}

impl<'a> SerialManager<'a> {
    pub fn new(port_name: &'a str, timeout_ms: u64) -> Self {
        SerialManager {
            port_name,
            timeout_ms,
        }
    }

    pub fn send_data(&self, data: Vec<u8>) -> Result<Vec<u8>, KSError> {
        let (tx, rx) = mpsc::channel();
        let mut port = serialport::new(self.port_name, BAUD_RATE)
            .timeout(Duration::from_millis(self.timeout_ms))
            .open()
            .map_err(|e| KSError::SerialManagerError("Fail open port".to_string()))?;

        let mut clone = port
            .try_clone()
            .map_err(|e| KSError::SerialManagerError("Fail to clone port".to_string()))?;

        thread::spawn(move || {
            match clone
                .write_all(&data)
                .map_err(|_e| KSError::SerialManagerError("Fail write port error".to_string()))
            {
                Ok(_) => tx.send(true),
                Err(_) => tx.send(false),
            }
        });

        match rx.recv() {
            Ok(result) => {
                if result {
                    // need improve
                    // open 3k bytes as the read buffer
                    let buffer_size = 3096;

                    let mut read_data_buf = vec![0; buffer_size];

                    let length =
                        port.read(read_data_buf.as_mut_slice())
                            .map_err(|e| match e.kind() {
                                ErrorKind::TimedOut => KSError::SerialTimeout,
                                _ => KSError::SerialManagerError("notKnow error".to_string()),
                            })?;

                    let received_data = read_data_buf.as_slice();
                    let result = received_data[..length].to_vec();
                    port.clear(serialport::ClearBuffer::All);
                    Ok(result)
                } else {
                    Err(KSError::SerialManagerError("send data error".to_string()))
                }
            }
            Err(_) => Err(KSError::SerialManagerError(
                "thread receive error".to_string(),
            )),
        }
    }
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;
    use hex;

    #[test]
    // this test function rely on secure element
    fn it_should_send_data_to_se() {
        let port_name = "/dev/ttyMT1";
        // set timeout to 100s
        const TIMEOUT_MS: u64 = 100000;
        let serialManger = SerialManager::new(port_name, TIMEOUT_MS);
        let version_sig: Vec<u8> = vec![02, 00, 00, 06, 00, 01, 00, 02, 01, 02, 03, 07];

        let result = serialManger.send_data(version_sig).unwrap();

        let expected = hex::decode("020000360001000201020106000c312e302e312e303030303030010f00041010000001180001010102000400000088021000010000020002000003ad").unwrap();

        assert_eq!(result, expected);
    }
}
