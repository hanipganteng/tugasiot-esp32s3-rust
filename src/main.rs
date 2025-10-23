#![no_std]
#![no_main]
extern crate alloc;

use esp_idf_sys::*;
use esp_idf_hal::{delay::Ets, gpio::PinDriver, peripherals::Peripherals};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    nvs::EspDefaultNvsPartition,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi},
};
use embedded_dht_rs::dht22::Dht22;
use log::{info, error};
use anyhow::{Result, anyhow};
use serde_json::{json, Value};
use alloc::{boxed::Box, string::{String, ToString}, ffi::CString, format, vec::Vec};
use core::ffi::c_void;
use sha2::{Digest, Sha256};

// OTA Constants
const OTA_REQUEST_TOPIC: &str = "v1/devices/me/attributes/request/";
const OTA_RESPONSE_TOPIC: &str = "v1/devices/me/attributes/response/";
const OTA_FIRMWARE_REQUEST_TOPIC: &str = "v2/fw/request";
const OTA_FIRMWARE_RESPONSE_TOPIC: &str = "v2/fw/response";
const OTA_TELEMETRY_TOPIC: &str = "v1/devices/me/telemetry";

// OTA Shared Attributes
const FW_TITLE_ATTR: &str = "fw_title";
const FW_VERSION_ATTR: &str = "fw_version";
const FW_SIZE_ATTR: &str = "fw_size";
const FW_CHECKSUM_ATTR: &str = "fw_checksum";
const FW_CHECKSUM_ALG_ATTR: &str = "fw_checksum_algorithm";
const FW_STATE_ATTR: &str = "fw_state";

#[inline(always)]
fn ms_to_ticks(ms: u32) -> u32 {
    (ms as u64 * configTICK_RATE_HZ as u64 / 1000) as u32
}

#[derive(PartialEq, Debug)]
enum OtaState {
    Idle,
    Downloading,
    Downloaded,
    Verifying,
    Updating,
    Updated,
    Failed(String),
}

struct OtaManager {
    current_fw_title: String,
    current_fw_version: String,
    fw_title: Option<String>,
    fw_version: Option<String>,
    fw_size: Option<u32>,
    fw_checksum: Option<String>,
    fw_checksum_algorithm: Option<String>,
    ota_state: OtaState,
    request_id: u32,
    firmware_request_id: u32,
    current_chunk: u32,
    ota_handle: esp_ota_handle_t,
    ota_partition: *const esp_partition_t,
    received_size: usize,
    sha256_hasher: Sha256,
    partial_firmware_data: Vec<u8>,
    ota_start_time: Option<i64>,
    ota_timeout_ms: i64,
}

impl OtaManager {
    fn new() -> Self {
        // Log and verify partition table
        unsafe {
            let otadata_partition = esp_partition_find_first(
                esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_DATA_OTA,
                core::ptr::null()
            );
            if !otadata_partition.is_null() {
                info!("Found otadata partition at {:p}", otadata_partition);
            } else {
                error!("No otadata partition found");
            }
            let mut ota_partitions_found = 0;
            for subtype in &[esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_0, esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_1] {
                let mut iterator = esp_partition_find(
                    esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                    *subtype,
                    core::ptr::null()
                );
                while !iterator.is_null() {
                    let partition = esp_partition_get(iterator);
                    let label = core::ffi::CStr::from_ptr((*partition).label.as_ptr()).to_str().unwrap_or("unknown");
                    info!("Found OTA partition: {}, subtype: {:?}, address: 0x{:x}, size: 0x{:x}",
                        label, (*partition).subtype, (*partition).address, (*partition).size);
                    ota_partitions_found += 1;
                    iterator = esp_partition_next(iterator);
                }
                esp_partition_iterator_release(iterator);
            }
            if ota_partitions_found < 2 {
                error!("Insufficient OTA partitions found: {}. Need at least 2 for OTA.", ota_partitions_found);
            } else {
                info!("Found {} OTA partitions, sufficient for OTA", ota_partitions_found);
            }
            let running_partition = esp_ota_get_running_partition();
            if !running_partition.is_null() {
                let label = core::ffi::CStr::from_ptr((*running_partition).label.as_ptr()).to_str().unwrap_or("unknown");
                info!("Current running partition: {}, subtype: {:?}, address: 0x{:x}, size: 0x{:x}",
                    label, (*running_partition).subtype, (*running_partition).address, (*running_partition).size);
            } else {
                error!("No running partition detected");
            }
        }
        Self {
            current_fw_title: "ESP32-S3 DHT22".to_string(),
            current_fw_version: "esp32_ota".to_string(),
            fw_title: None,
            fw_version: None,
            fw_size: None,
            fw_checksum: None,
            fw_checksum_algorithm: None,
            ota_state: OtaState::Idle,
            request_id: 0,
            firmware_request_id: 0,
            current_chunk: 0,
            ota_handle: 0,
            ota_partition: core::ptr::null(),
            received_size: 0,
            sha256_hasher: Sha256::new(),
            partial_firmware_data: Vec::new(),
            ota_start_time: None,
            ota_timeout_ms: 30_000, // Timeout 30 detik
        }
    }

    fn handle_shared_attributes(&mut self, attributes: &str, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        if self.ota_state != OtaState::Idle {
            info!("Ignoring attributes: OTA in progress with state {:?}", self.ota_state);
            return Ok(());
        }
        let attrs: Value = serde_json::from_str(attributes)?;
        info!("Raw attributes received: {}", attributes);
        let shared_attrs = attrs.get("shared").ok_or_else(|| anyhow!("Missing 'shared' object in attributes"))?;
        let mut result = Ok(());
        if let Some(fw_title) = shared_attrs.get(FW_TITLE_ATTR).and_then(|v| v.as_str()) {
            self.fw_title = Some(fw_title.trim().to_string());
            info!("Received fw_title: '{}'", fw_title);
        }
        if let Some(fw_version) = shared_attrs.get(FW_VERSION_ATTR).and_then(|v| v.as_str()) {
            self.fw_version = Some(fw_version.trim().to_string());
            info!("Received fw_version: '{}'", fw_version);
        }
        if let Some(fw_size) = shared_attrs.get(FW_SIZE_ATTR).and_then(|v| v.as_u64()) {
            self.fw_size = Some(fw_size as u32);
            info!("Received fw_size: {}", fw_size);
        }
        if let Some(fw_checksum) = shared_attrs.get(FW_CHECKSUM_ATTR).and_then(|v| v.as_str()) {
            self.fw_checksum = Some(fw_checksum.trim().to_string());
            info!("Received fw_checksum: '{}'", fw_checksum);
        }
        if let Some(fw_checksum_alg) = shared_attrs.get(FW_CHECKSUM_ALG_ATTR).and_then(|v| v.as_str()) {
            self.fw_checksum_algorithm = Some(fw_checksum_alg.trim().to_string());
            info!("Received fw_checksum_algorithm: '{}'", fw_checksum_alg);
        }
        if let (Some(fw_title), Some(fw_version)) = (&self.fw_title, &self.fw_version) {
            info!("Comparing fw_title: '{}' vs '{}', fw_version: '{}' vs '{}'",
                fw_title, self.current_fw_title, fw_version, self.current_fw_version);
            if fw_title.trim() != self.current_fw_title.trim() || fw_version.trim() != self.current_fw_version.trim() {
                info!("New firmware available: {} {}", fw_title, fw_version);
                self.ota_state = OtaState::Downloading;
                self.firmware_request_id += 1;
                self.current_chunk = 0;
                self.received_size = 0;
                self.sha256_hasher = Sha256::new();
                self.ota_start_time = Some(unsafe { esp_timer_get_time() / 1000 });
                unsafe {
                    self.ota_partition = esp_ota_get_next_update_partition(core::ptr::null());
                    if self.ota_partition.is_null() {
                        error!("esp_ota_get_next_update_partition failed. Attempting manual partition selection...");
                        let running_partition = esp_ota_get_running_partition();
                        if !running_partition.is_null() {
                            let label = core::ffi::CStr::from_ptr((*running_partition).label.as_ptr()).to_str().unwrap_or("unknown");
                            info!("Running partition: {}, subtype: {:?}, address: 0x{:x}", label, (*running_partition).subtype, (*running_partition).address);
                        } else {
                            error!("No running partition detected");
                        }
                        if !running_partition.is_null() && (*running_partition).subtype == esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_FACTORY {
                            info!("Running from factory subtype, selecting ota_0 as update partition");
                            let mut iterator = esp_partition_find(
                                esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                                esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_0,
                                core::ptr::null()
                            );
                            if !iterator.is_null() {
                                self.ota_partition = esp_partition_get(iterator);
                                esp_partition_iterator_release(iterator);
                            }
                        } else {
                            for subtype in &[esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_0, esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_1] {
                                let mut iterator = esp_partition_find(
                                    esp_partition_type_t_ESP_PARTITION_TYPE_APP,
                                    *subtype,
                                    core::ptr::null()
                                );
                                while !iterator.is_null() {
                                    let partition = esp_partition_get(iterator);
                                    let label = core::ffi::CStr::from_ptr((*partition).label.as_ptr()).to_str().unwrap_or("unknown");
                                    info!("Checking partition: {}, subtype: {:?}, address: 0x{:x}", label, (*partition).subtype, (*partition).address);
                                    if !running_partition.is_null() && partition != running_partition {
                                        self.ota_partition = partition;
                                        break;
                                    }
                                    iterator = esp_partition_next(iterator);
                                }
                                esp_partition_iterator_release(iterator);
                                if !self.ota_partition.is_null() {
                                    break;
                                }
                            }
                        }
                    }
                    if self.ota_partition.is_null() {
                        error!("No valid OTA partition found for update");
                        self.ota_state = OtaState::Failed("No valid OTA partition found".to_string());
                        result = Err(anyhow!("No valid OTA partition found"));
                    } else {
                        let label = core::ffi::CStr::from_ptr((*self.ota_partition).label.as_ptr()).to_str().unwrap_or("unknown");
                        info!("Selected OTA partition: {}, subtype: {:?}, address: 0x{:x}, size: 0x{:x}",
                            label, (*self.ota_partition).subtype, (*self.ota_partition).address, (*self.ota_partition).size);
                        let res = esp_partition_erase_range(self.ota_partition, 0, (*self.ota_partition).size as usize);
                        if res != ESP_OK {
                            self.ota_state = OtaState::Failed(format!("Failed to erase OTA partition: {}", res));
                            result = Err(anyhow!("Failed to erase OTA partition: {}", res));
                        } else {
                            let res = esp_ota_begin(self.ota_partition, self.fw_size.unwrap_or(0) as usize, &mut self.ota_handle);
                            if res != ESP_OK {
                                self.ota_state = OtaState::Failed(format!("Failed to begin OTA: {}", res));
                                result = Err(anyhow!("Failed to begin OTA: {}", res));
                            } else {
                                if let Err(e) = self.request_firmware_chunk(mqtt_client) {
                                    self.ota_state = OtaState::Failed(format!("Failed to request firmware chunk: {}", e));
                                    result = Err(e);
                                }
                            }
                        }
                    }
                    if let Err(e) = self.send_ota_telemetry(mqtt_client) {
                        error!("Failed to send OTA telemetry: {:?}", e);
                    }
                }
            } else {
                info!("No new firmware detected: title and version match current");
                // Reset atribut untuk mencegah pemrosesan ulang
                self.fw_title = None;
                self.fw_version = None;
                self.fw_size = None;
                self.fw_checksum = None;
                self.fw_checksum_algorithm = None;
            }
        } else {
            info!("Incomplete firmware attributes: fw_title={:?}, fw_version={:?}", self.fw_title, self.fw_version);
            result = Err(anyhow!("Incomplete firmware attributes received"));
        }
        result
    }

    fn request_firmware_info(&mut self, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        self.request_id += 1;
        let request_topic = format!("{}{}", OTA_REQUEST_TOPIC, self.request_id);
        let payload = json!({
            "sharedKeys": format!("{},{},{},{},{}",
                FW_TITLE_ATTR, FW_VERSION_ATTR, FW_SIZE_ATTR, FW_CHECKSUM_ATTR, FW_CHECKSUM_ALG_ATTR)
        });
        Self::mqtt_publish(mqtt_client, &request_topic, &payload.to_string())?;
        info!("Requested firmware info, topic: {}", request_topic);
        Ok(())
    }

    fn request_firmware_chunk(&mut self, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        if let Some(fw_size) = self.fw_size {
            if self.received_size >= fw_size as usize {
                info!("All firmware chunks received, no further requests needed");
                return Ok(());
            }
        }
        let topic = format!("{}/{}/chunk/{}", OTA_FIRMWARE_REQUEST_TOPIC, self.firmware_request_id, self.current_chunk);
        let payload = "4096".to_string(); // Ubah ke 4096 byte untuk efisiensi
        Self::mqtt_publish(mqtt_client, &topic, &payload)?;
        info!("Requested firmware chunk {}, topic: {}", self.current_chunk, topic);
        Ok(())
    }

    fn handle_firmware_chunk(&mut self, data: &[u8], chunk_index: u32, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        if chunk_index != self.current_chunk {
            error!("Received chunk {} but expected chunk {}, ignoring", chunk_index, self.current_chunk);
            return Ok(());
        }
        if data.len() == 0 {
            if self.received_size == self.fw_size.unwrap_or(0) as usize {
                info!("Received empty chunk, download complete");
                self.ota_state = OtaState::Downloaded;
                unsafe {
                    let res = esp_ota_end(self.ota_handle);
                    if res != ESP_OK {
                        self.ota_state = OtaState::Failed(format!("Failed to end OTA: {}", res));
                        self.send_ota_telemetry(mqtt_client)?;
                        return Err(anyhow!("Failed to end OTA: {}", res));
                    }
                }
                self.process_firmware(mqtt_client)?;
                return Ok(());
            } else {
                self.ota_state = OtaState::Failed("Received empty chunk but size mismatch".to_string());
                self.send_ota_telemetry(mqtt_client)?;
                return Err(anyhow!("Empty chunk received prematurely"));
            }
        }
        self.received_size += data.len();
        info!("Received chunk {}, size: {}, total received: {}", self.current_chunk, data.len(), self.received_size);
        if let Some(fw_size) = self.fw_size {
            let percentage = (self.received_size as f32 / fw_size as f32) * 100.0;
            info!("Download progress: {:.2}% ({} / {})", percentage, self.received_size, fw_size);
            if self.received_size >= fw_size as usize {
                info!("Download complete: received {} bytes of {} bytes", self.received_size, fw_size);
            } else {
                info!("Download not complete: received {} bytes, need {} bytes", self.received_size, fw_size);
            }
        }
        self.sha256_hasher.update(data);
        unsafe {
            let res = esp_ota_write(self.ota_handle, data.as_ptr() as *const c_void, data.len());
            if res != ESP_OK {
                self.ota_state = OtaState::Failed(format!("Failed to write OTA data: {}", res));
                self.send_ota_telemetry(mqtt_client)?;
                return Err(anyhow!("Failed to write OTA data: {}", res));
            }
        }
        self.current_chunk += 1;
        if let Some(fw_size) = self.fw_size {
            if self.received_size >= fw_size as usize {
                self.ota_state = OtaState::Downloaded;
                unsafe {
                    let res = esp_ota_end(self.ota_handle);
                    if res != ESP_OK {
                        self.ota_state = OtaState::Failed(format!("Failed to end OTA: {}", res));
                        self.send_ota_telemetry(mqtt_client)?;
                        return Err(anyhow!("Failed to end OTA: {}", res));
                    }
                }
                self.process_firmware(mqtt_client)?;
            } else {
                self.request_firmware_chunk(mqtt_client)?;
            }
        }
        Ok(())
    }

    fn process_firmware(&mut self, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        self.ota_state = OtaState::Verifying;
        self.send_ota_telemetry(mqtt_client)?;
        if let Some(checksum) = &self.fw_checksum {
            let computed_checksum = {
                let result = self.sha256_hasher.clone().finalize();
                result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            };
            info!("Computed checksum: {}, Expected checksum: {}", computed_checksum, checksum);
            if computed_checksum == *checksum {
                self.ota_state = OtaState::Updating;
                self.send_ota_telemetry(mqtt_client)?;
                unsafe {
                    let res = esp_ota_set_boot_partition(self.ota_partition);
                    if res != ESP_OK {
                        self.ota_state = OtaState::Failed(format!("Failed to set boot partition: {}", res));
                        self.send_ota_telemetry(mqtt_client)?;
                        return Err(anyhow!("Failed to set boot partition: {}", res));
                    }
                }
                self.current_fw_title = self.fw_title.clone().unwrap_or_default();
                self.current_fw_version = self.fw_version.clone().unwrap_or_default();
                // Reset OTA attributes
                self.fw_title = None;
                self.fw_version = None;
                self.fw_size = None;
                self.fw_checksum = None;
                self.fw_checksum_algorithm = None;
                self.current_chunk = 0;
                self.received_size = 0;
                self.partial_firmware_data.clear();
                self.sha256_hasher = Sha256::new();
                self.ota_start_time = None;
                self.ota_state = OtaState::Updated;
                self.send_ota_telemetry(mqtt_client)?;
                info!("Firmware update successful, restarting...");
                unsafe { esp_restart(); }
            } else {
                self.ota_state = OtaState::Failed("Checksum verification failed".to_string());
                self.send_ota_telemetry(mqtt_client)?;
                return Err(anyhow!("Checksum verification failed"));
            }
        } else {
            self.ota_state = OtaState::Failed("No checksum provided".to_string());
            self.send_ota_telemetry(mqtt_client)?;
            return Err(anyhow!("No checksum provided"));
        }
    }

    fn check_timeout(&mut self, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        if self.ota_state != OtaState::Idle {
            if let Some(start_time) = self.ota_start_time {
                let current_time = unsafe { esp_timer_get_time() / 1000 }; // Waktu dalam ms
                if current_time - start_time > self.ota_timeout_ms {
                    self.ota_state = OtaState::Failed("OTA timeout".to_string());
                    self.send_ota_telemetry(mqtt_client)?;
                    // Reset OTA state
                    self.fw_title = None;
                    self.fw_version = None;
                    self.fw_size = None;
                    self.fw_checksum = None;
                    self.fw_checksum_algorithm = None;
                    self.current_chunk = 0;
                    self.received_size = 0;
                    self.partial_firmware_data.clear();
                    self.sha256_hasher = Sha256::new();
                    self.ota_start_time = None;
                    unsafe {
                        if self.ota_handle != 0 {
                            esp_ota_end(self.ota_handle);
                            self.ota_handle = 0;
                        }
                    }
                    return Err(anyhow!("OTA timeout"));
                }
            } else {
                self.ota_start_time = Some(unsafe { esp_timer_get_time() / 1000 });
            }
        }
        Ok(())
    }

    fn send_ota_telemetry(&self, mqtt_client: *mut esp_mqtt_client) -> Result<()> {
        let payload = match &self.ota_state {
            OtaState::Idle => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "IDLE"
            }).to_string(),
            OtaState::Downloading => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "DOWNLOADING"
            }).to_string(),
            OtaState::Downloaded => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "DOWNLOADED"
            }).to_string(),
            OtaState::Verifying => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "VERIFYING"
            }).to_string(),
            OtaState::Updating => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "UPDATING"
            }).to_string(),
            OtaState::Updated => json!({
                "current_fw_title": &self.current_fw_title,
                "current_fw_version": &self.current_fw_version,
                FW_STATE_ATTR: "UPDATED"
            }).to_string(),
            OtaState::Failed(error) => json!({
                FW_STATE_ATTR: "FAILED",
                "fw_error": error
            }).to_string(),
        };
        Self::mqtt_publish(mqtt_client, OTA_TELEMETRY_TOPIC, &payload)?;
        info!("Sent OTA telemetry: {}", payload);
        Ok(())
    }

    fn mqtt_publish(mqtt_client: *mut esp_mqtt_client, topic: &str, data: &str) -> Result<()> {
        unsafe {
            let topic_cstr = CString::new(topic)?;
            let data_cstr = CString::new(data)?;
            let msg_id = esp_mqtt_client_publish(
                mqtt_client,
                topic_cstr.as_ptr(),
                data_cstr.as_ptr(),
                data.len() as i32,
                1,
                0
            );
            if msg_id < 0 {
                Err(anyhow!("Failed to publish message to {}: {}", topic, msg_id))
            } else {
                info!("Published message to {} with ID: {}", topic, msg_id);
                Ok(())
            }
        }
    }
}

struct SimpleMqttClient {
    client: *mut esp_mqtt_client,
}

impl SimpleMqttClient {
    fn new(broker_url: &str, username: &str, password: &str, client_id: &str, ota_manager_ptr: *mut OtaManager) -> Result<Self> {
        unsafe {
            let broker_url_cstr = CString::new(broker_url)?;
            let username_cstr = CString::new(username)?;
            let password_cstr = CString::new(password)?;
            let client_id_cstr = CString::new(client_id)?;
            let config = esp_mqtt_client_config_t {
                broker: esp_mqtt_client_config_t_broker_t {
                    address: esp_mqtt_client_config_t_broker_t_address_t {
                        uri: broker_url_cstr.as_ptr(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                credentials: esp_mqtt_client_config_t_credentials_t {
                    username: username_cstr.as_ptr(),
                    client_id: client_id_cstr.as_ptr(),
                    authentication: esp_mqtt_client_config_t_credentials_t_authentication_t {
                        password: password_cstr.as_ptr(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                buffer: esp_mqtt_client_config_t_buffer_t {
                    size: 4096,
                    out_size: 4096,
                    ..Default::default()
                },
                ..Default::default()
            };
            let client = esp_mqtt_client_init(&config);
            if client.is_null() {
                return Err(anyhow!("Failed to initialize MQTT client"));
            }
            esp_mqtt_client_register_event(
                client,
                esp_mqtt_event_id_t_MQTT_EVENT_ANY,
                Some(Self::mqtt_event_handler),
                ota_manager_ptr as *mut c_void
            );
            let err = esp_mqtt_client_start(client);
            if err != ESP_OK {
                esp_mqtt_client_destroy(client);
                return Err(anyhow!("Failed to start MQTT client, error code: {}", err));
            }
            vTaskDelay(ms_to_ticks(5000));
            Ok(Self { client })
        }
    }

    extern "C" fn mqtt_event_handler(
        handler_args: *mut c_void,
        _base: *const u8,
        event_id: i32,
        event_data: *mut c_void
    ) {
        unsafe {
            let ota_manager = handler_args as *mut OtaManager;
            if ota_manager.is_null() {
                error!("OTA manager pointer is null");
                return;
            }
            let event = &*(event_data as *mut esp_mqtt_event_t);
            if event_id == esp_mqtt_event_id_t_MQTT_EVENT_DATA as i32 {
                let topic_len = event.topic_len as usize;
                let data_len = event.data_len as usize;
                if topic_len > 0 && data_len > 0 {
                    let topic_slice = core::slice::from_raw_parts(event.topic as *const u8, topic_len);
                    let topic = core::str::from_utf8(topic_slice).unwrap_or("");
                    info!("Received MQTT message on topic: {}", topic);
                    let data_slice = core::slice::from_raw_parts(event.data as *const u8, data_len);
                    if topic.starts_with(OTA_RESPONSE_TOPIC) {
                        let topic_parts: Vec<&str> = topic.split('/').collect();
                        if let Some(req_id_str) = topic_parts.last() {
                            if let Ok(req_id) = req_id_str.parse::<u32>() {
                                if req_id != (*ota_manager).request_id {
                                    info!("Ignoring duplicate or outdated OTA response for request_id: {}", req_id);
                                    return;
                                }
                            }
                        }
                        if let Ok(data_str) = core::str::from_utf8(data_slice) {
                            info!("OTA response data: {}", data_str);
                            if let Err(e) = (*ota_manager).handle_shared_attributes(data_str, event.client) {
                                error!("Failed to handle OTA attributes: {:?}", e);
                            }
                        } else {
                            error!("Invalid UTF-8 in OTA response");
                        }
                    } else if topic.starts_with(&format!("{}/{}/", OTA_FIRMWARE_RESPONSE_TOPIC, (*ota_manager).firmware_request_id)) {
                        let total_len = event.total_data_len as usize;
                        let offset = event.current_data_offset as usize;
                        let chunk_data_len = event.data_len as usize;
                        let data_slice = core::slice::from_raw_parts(event.data as *const u8, chunk_data_len);
                        if offset == 0 {
                            (*ota_manager).partial_firmware_data.clear();
                            (*ota_manager).partial_firmware_data.extend_from_slice(data_slice);
                        } else {
                            (*ota_manager).partial_firmware_data.extend_from_slice(data_slice);
                        }
                        if offset + chunk_data_len >= total_len {
                            let topic_parts: Vec<&str> = topic.split('/').collect();
                            if let Some(chunk_str) = topic_parts.last() {
                                if let Ok(chunk_index) = chunk_str.parse::<u32>() {
                                    if topic.starts_with(&format!("{}/{}/", OTA_FIRMWARE_RESPONSE_TOPIC, (*ota_manager).firmware_request_id)) {
                                        info!("Received complete firmware chunk for request ID: {}, chunk: {}, data length: {}",
                                            (*ota_manager).firmware_request_id, chunk_index, (*ota_manager).partial_firmware_data.len());
                                        if let Err(e) = (*ota_manager).handle_firmware_chunk(&(*ota_manager).partial_firmware_data, chunk_index, event.client) {
                                            error!("Failed to handle firmware chunk: {:?}", e);
                                        }
                                    } else {
                                        info!("Ignoring outdated firmware chunk for request_id: {}", (*ota_manager).firmware_request_id);
                                    }
                                } else {
                                    error!("Invalid chunk index in topic: {}", topic);
                                }
                            }
                            (*ota_manager).partial_firmware_data.clear();
                        }
                    } else {
                        info!("Received MQTT message on unexpected topic: {}", topic);
                    }
                }
            }
        }
    }

    fn publish(&self, topic: &str, data: &str) -> Result<()> {
        OtaManager::mqtt_publish(self.client, topic, data)
    }

    fn subscribe(&self, topic: &str) -> Result<()> {
        unsafe {
            let topic_cstr = CString::new(topic)?;
            let result = esp_mqtt_client_subscribe_single(
                self.client,
                topic_cstr.as_ptr(),
                1
            );
            if result == -1 {
                Err(anyhow!("Failed to subscribe to topic: {}", topic))
            } else {
                info!("Subscribed to: {}", topic);
                Ok(())
            }
        }
    }
}

impl Drop for SimpleMqttClient {
    fn drop(&mut self) {
        unsafe {
            esp_mqtt_client_stop(self.client);
            esp_mqtt_client_destroy(self.client);
        }
    }
}

fn send_telemetry(
    mqtt_client: &SimpleMqttClient,
    temperature: f32,
    humidity: f32
) -> Result<()> {
    let payload = json!({
        "temperature": temperature,
        "humidity": humidity
    }).to_string();
    mqtt_client.publish(OTA_TELEMETRY_TOPIC, &payload)?;
    info!("Data sent to ThingsBoard: {}", payload);
    Ok(())
}

fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> Result<()> {
    let ssid = "LANCAR JAYA";
    let password = "jaya12345";
    let wifi_config = Configuration::Client(ClientConfiguration {
        ssid: heapless::String::try_from(ssid).unwrap(),
        password: heapless::String::try_from(password).unwrap(),
        auth_method: AuthMethod::WPA2Personal,
        ..Default::default()
    });
    wifi.set_configuration(&wifi_config)?;
    wifi.start()?;
    wifi.connect()?;
    wifi.wait_netif_up()?;
    let ip_info = wifi.wifi().sta_netif().get_ip_info()?;
    info!("WiFi Connected, IP: {}", ip_info.ip);
    Ok(())
}

#[no_mangle]
fn main() -> i32 {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    info!("Starting DHT22 + WiFi + MQTT application with OTA");
    let peripherals = Peripherals::take().unwrap();
    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs)).unwrap(),
        sys_loop,
    ).unwrap();
    
    if let Err(e) = connect_wifi(&mut wifi) {
        error!("Failed to connect to WiFi: {:?}", e);
        return -1;
    }
    let pin = PinDriver::input_output_od(peripherals.pins.gpio4).unwrap();
    let mut dht22 = Dht22::new(pin, Ets);
    info!("Connecting to MQTT broker...");
    let mut ota_manager = Box::new(OtaManager::new());
    let ota_manager_ptr = &mut *ota_manager as *mut OtaManager;
    let mqtt_client = match SimpleMqttClient::new(
        "mqtt://thingsboard.cloud:1883",
        "pNQ4wOKQOY9tUPQHaz7H",
        "",                      // Replace with actual password if needed
        "esp32_dht22_client",    // Replace with a unique client ID if needed
        ota_manager_ptr
    ) {
        Ok(client) => {
            info!("Connected to ThingsBoard MQTT broker");
            if let Err(e) = client.subscribe("v1/devices/me/attributes/response/+") {
                error!("Failed to subscribe to OTA response: {:?}", e);
            }
            if let Err(e) = client.subscribe("v1/devices/me/attributes") {
                error!("Failed to subscribe to attributes: {:?}", e);
            }
            if let Err(e) = client.subscribe("v2/fw/response/+/chunk/+") {
                error!("Failed to subscribe to firmware response: {:?}", e);
            }
            client
        },
        Err(e) => {
            error!("Failed to connect to MQTT: {:?}", e);
            return -1;
        }
    };
    if let Err(e) = ota_manager.request_firmware_info(mqtt_client.client) {
        error!("Failed to request firmware info: {:?}", e);
    }
    let mut counter = 0;
    let mut ota_check_counter = 0;
    loop {
        counter += 1;
        ota_check_counter += 1;
        if ota_check_counter >= 6 && ota_manager.ota_state == OtaState::Idle {
            ota_check_counter = 0;
            if ota_manager.fw_title.is_none() && ota_manager.fw_version.is_none() {
                if let Err(e) = ota_manager.request_firmware_info(mqtt_client.client) {
                    error!("Failed to request firmware info: {:?}", e);
                }
            } else {
                info!("Skipping firmware info request: OTA attributes already present");
            }
        }
        if let Err(e) = ota_manager.check_timeout(mqtt_client.client) {
            error!("OTA timeout error: {:?}", e);
        }
        let reading = match dht22.read() {
            Ok(r) => r,
            Err(e) => {
                error!("DHT22 read error: {:?}", e);
                unsafe { vTaskDelay(ms_to_ticks(1000)); }
                continue;
            }
        };
        let temperature = reading.temperature;
        let humidity = reading.humidity;
        info!("=== Reading {} ===", counter);
        info!("Temperature: {:.2} °C", temperature);
        info!("Humidity: {:.2} %", humidity);
        if let Err(e) = send_telemetry(
            &mqtt_client,
            temperature,
            humidity
        ) {
            error!("Failed to send telemetry: {:?}", e);
        }
        if ota_manager.ota_state != OtaState::Idle {
            if let Err(e) = ota_manager.send_ota_telemetry(mqtt_client.client) {
                error!("Failed to send OTA telemetry: {:?}", e);
            }
        }
        unsafe { vTaskDelay(ms_to_ticks(5000)); }
    }
}
