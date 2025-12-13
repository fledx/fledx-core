use control_plane::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() {
    let doc = ApiDoc::openapi();
    let json = doc
        .to_pretty_json()
        .expect("serialize openapi document to json");
    println!("{json}");
}
