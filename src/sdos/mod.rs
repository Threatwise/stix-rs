use thiserror::Error;

mod attack_pattern;
pub use attack_pattern::AttackPattern;

mod campaign;
pub use campaign::Campaign;

mod course_of_action;
pub use course_of_action::CourseOfAction;

mod grouping;
pub use grouping::Grouping;

mod incident;
pub use incident::Incident;

mod infrastructure;
pub use infrastructure::Infrastructure;

mod intrusion_set;
pub use intrusion_set::IntrusionSet;

mod location;
pub use location::Location;

mod malware_analysis;
pub use malware_analysis::MalwareAnalysis;

mod note;
pub use note::Note;

mod observed_data;
pub use observed_data::ObservedData;

mod opinion;
pub use opinion::Opinion;

mod report;
pub use report::Report;

mod threat_actor;
pub use threat_actor::ThreatActor;

mod tool;
pub use tool::Tool;

mod vulnerability;
pub use vulnerability::Vulnerability;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}
