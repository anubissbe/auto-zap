use actix_web::{web, App, HttpServer, HttpResponse};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().route("/", web::get().to(|| async { HttpResponse::Ok().body("Hello from Rust") }))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
