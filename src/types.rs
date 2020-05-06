use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AddParams {
    pub name: Option<String>,
    pub password: Option<String>,
    pub curve_type: Option<String>,
    pub address_format: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ImportParams {
    pub phrase: String,
    pub name: Option<String>,
    pub password: Option<String>,
    pub curve_type: Option<String>,
    pub address_format: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ExportParams {
    pub name: String,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SignMessageParams {
    pub name: String,
    pub password: Option<String>,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct VerfiyMessageParams {
    pub name: String,
    pub message: String,
    pub signature: String,
}
