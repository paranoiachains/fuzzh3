use std::collections::HashMap;

#[derive(Clone)]
pub struct Request {
    pub path: String,
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub headers: HashMap<String, String>,
}

impl Request {
    pub fn new(
        scheme: &str,
        host: &str,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            scheme: scheme.to_string(),
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            headers,
        })
    }

    pub fn to_quiche(&self) -> Vec<quiche::h3::Header> {
        let mut headers = vec![
            quiche::h3::Header::new(b":method", self.method.as_bytes()),
            quiche::h3::Header::new(b":scheme", self.scheme.as_bytes()),
            quiche::h3::Header::new(b":authority", self.host.as_bytes()),
            quiche::h3::Header::new(b":path", self.path.as_bytes()),
        ];

        for (k, v) in &self.headers {
            headers.push(quiche::h3::Header::new(k.as_bytes(), v.as_bytes()));
        }

        headers
    }

    pub fn with_path(&self, path: &str) -> Self {
        let mut r = self.clone();
        r.path = format!("/{}", path);
        r
    }
}

pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, headers: HashMap<String, String>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    pub fn body_to_string(&self) -> anyhow::Result<String> {
        Ok(String::from_utf8_lossy(&self.body).into_owned())
    }
}
