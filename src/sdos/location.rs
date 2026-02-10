use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, StixObject};

/// Location SDO
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Location {
    #[serde(flatten)]
    pub common: CommonProperties,

    pub name: Option<String>,
    pub description: Option<String>,

    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub precision: Option<f64>,

    pub region: Option<String>,
    pub country: Option<String>,
    pub administrative_area: Option<String>,
    pub city: Option<String>,
    pub street_address: Option<String>,
    pub postal_code: Option<String>,
}

impl Location { pub fn builder() -> LocationBuilder { LocationBuilder::default() } }

#[derive(Debug, Default)]
pub struct LocationBuilder { name: Option<String>, description: Option<String>, latitude: Option<f64>, longitude: Option<f64>, precision: Option<f64>, region: Option<String>, country: Option<String>, administrative_area: Option<String>, city: Option<String>, street_address: Option<String>, postal_code: Option<String>, created_by_ref: Option<String> }

impl LocationBuilder {
    pub fn name(mut self, n: impl Into<String>) -> Self { self.name = Some(n.into()); self }
    pub fn description(mut self, d: impl Into<String>) -> Self { self.description = Some(d.into()); self }
    pub fn latitude(mut self, lat: f64) -> Self { self.latitude = Some(lat); self }
    pub fn longitude(mut self, lon: f64) -> Self { self.longitude = Some(lon); self }
    pub fn precision(mut self, p: f64) -> Self { self.precision = Some(p); self }
    pub fn region(mut self, r: impl Into<String>) -> Self { self.region = Some(r.into()); self }
    pub fn country(mut self, c: impl Into<String>) -> Self { self.country = Some(c.into()); self }
    pub fn administrative_area(mut self, a: impl Into<String>) -> Self { self.administrative_area = Some(a.into()); self }
    pub fn city(mut self, c: impl Into<String>) -> Self { self.city = Some(c.into()); self }
    pub fn street_address(mut self, s: impl Into<String>) -> Self { self.street_address = Some(s.into()); self }
    pub fn postal_code(mut self, p: impl Into<String>) -> Self { self.postal_code = Some(p.into()); self }
    pub fn created_by_ref(mut self, r: impl Into<String>) -> Self { self.created_by_ref = Some(r.into()); self }

    pub fn build(self) -> Result<Location, super::BuilderError> {
        // STIX requires at least one of region, country, or (latitude and longitude).
        if self.region.is_none() && self.country.is_none() && !(self.latitude.is_some() && self.longitude.is_some()) {
            return Err(super::BuilderError::MissingField("one of region|country|(latitude+longitude)"));
        }

        let common = CommonProperties::new("location", self.created_by_ref);
        Ok(Location{
            common,
            name: self.name,
            description: self.description,
            latitude: self.latitude,
            longitude: self.longitude,
            precision: self.precision,
            region: self.region,
            country: self.country,
            administrative_area: self.administrative_area,
            city: self.city,
            street_address: self.street_address,
            postal_code: self.postal_code,
        })
    }
}

impl StixObject for Location { fn id(&self) -> &str { &self.common.id } fn type_(&self) -> &str { &self.common.r#type } fn created(&self) -> DateTime<Utc> { self.common.created } }

impl From<Location> for crate::StixObjectEnum { fn from(l: Location) -> Self { crate::StixObjectEnum::Location(l) } }

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn location_builder_and_serialize() {
        let loc = Location::builder().region("europe").build().unwrap();
        let s = serde_json::to_string(&loc).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v.get("type").and_then(Value::as_str).unwrap(), "location");
        assert!(v.get("region").is_some());
    }
}
