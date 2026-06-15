use std::io::Read;
use std::time::Duration;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT, CACHE_CONTROL, PRAGMA, ACCEPT, CONNECTION};

const MAX_RESPONSE_SIZE: usize = 65536; // 64KB

fn build_client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP istemci oluşturulamadı: {:?}", e))
}

fn common_headers(identity: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/timestamp-query"));
    
    let ua = format!("KilimcininKorOglu/kamusm-rs/{}", env!("CARGO_PKG_VERSION"));
    if let Ok(val) = HeaderValue::from_str(&ua) {
        headers.insert(USER_AGENT, val);
    }
    
    if let Ok(val) = HeaderValue::from_str(identity) {
        headers.insert("identity", val);
    }
    
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(ACCEPT, HeaderValue::from_static("text/html, image/gif, image/jpeg, */*; q=0.2"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    
    headers
}

/// Sends a timestamp request to the KamuSM server.
pub fn send_timestamp_request(host: &str, identity: &str, der: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let client = build_client()?;
    let headers = common_headers(identity);
    
    let resp = client.post(host)
        .headers(headers)
        .body(der.to_vec())
        .send()
        .map_err(|e| format!("İstek gönderilemedi: {:?}", e))?;
        
    let status = resp.status().as_u16();
    
    let mut body = Vec::new();
    resp.take(MAX_RESPONSE_SIZE as u64)
        .read_to_end(&mut body)
        .map_err(|e| format!("Yanıt gövdesi okunamadı: {:?}", e))?;
        
    Ok((status, body))
}

/// Sends a credit balance check request to the KamuSM server.
pub fn send_credit_request(host: &str, identity: &str, customer_id: u32, timestamp: u64) -> Result<(u16, String, Vec<u8>), String> {
    let client = build_client()?;
    let mut headers = common_headers(identity);
    
    headers.insert("credit_req", HeaderValue::from_str(&customer_id.to_string()).unwrap());
    headers.insert("credit_req_time", HeaderValue::from_str(&timestamp.to_string()).unwrap());
    
    let resp = client.post(host)
        .headers(headers)
        .body(Vec::new()) // ContentLength = 0
        .send()
        .map_err(|e| format!("Bakiye kontrolü isteği gönderilemedi: {:?}", e))?;
        
    let status = resp.status().as_u16();
    let content_type = resp.headers()
        .get(CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
        
    let mut body = Vec::new();
    resp.take(MAX_RESPONSE_SIZE as u64)
        .read_to_end(&mut body)
        .map_err(|e| format!("Yanıt gövdesi okunamadı: {:?}", e))?;
        
    Ok((status, content_type, body))
}
