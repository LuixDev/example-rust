use actix_cors::Cors;
use actix_web::{
    get, http, middleware, post, web::{self, Json}, App, Error, HttpRequest, HttpResponse, HttpServer, Responder
};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use chrono::{Duration, Utc};
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::{NoTls, Row};

use std::env;

#[derive(Debug, Serialize)]
struct Publicacion {
    imagep: String,
    nombre: String,
    id: i64,
    titulo: String,
    descripcion: String,
    imagen: String,
    fecha: String,
    like_count: i64,
    user_id: i64,
}

#[derive(Serialize)]
struct User {
    nombre: String,
    user_id: i64,
    categoria: String,
    imagep: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct LoginData {
    nombre: String,
    contrasena: String,
}
#[derive(Serialize)]
struct SearchResponse {
    success: bool,
    message: Option<String>,
    users: Option<Vec<User>>,
}

#[derive(Serialize)]
struct PerfilResponse {
    success: bool,
    message: String,
    imagep: Option<String>,
    image_fondo: Option<String>,
    nombre: Option<String>,
    categoria: Option<String>,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    message: Option<String>,
    data: Option<T>,
}

async fn connect_to_postgresql(pool: web::Data<Pool>) -> Result<deadpool_postgres::Client, Error> {
    pool.get()
        .await
        .map_err(|e| {
            eprintln!("Error al obtener cliente de la base de datos: {}", e);
            actix_web::error::ErrorInternalServerError("Error interno del servidor")
        })
}

#[post("/login")]
async fn login(
    pool: web::Data<Pool>,
    data: web::Json<LoginData>,
) -> Result<HttpResponse, Error> {
    println!("🔍 Intentando login con usuario: {}", data.nombre);

    let client = connect_to_postgresql(pool).await?;
    let row = client
        .query_opt(
            "SELECT user_id FROM datos WHERE nombre = $1 AND contrasena = $2",
            &[&data.nombre, &data.contrasena],
        )
        .await
        .map_err(|e| {
            eprintln!("❌ Error en consulta SQL: {}", e);
            actix_web::error::ErrorInternalServerError("Error en la base de datos")
        })?;

    if let Some(row) = row {
        let user_id: i64 = row.get(0);
        println!("✅ Usuario {} autenticado correctamente", data.nombre);

        let expiration = Utc::now()
            .checked_add_signed(Duration::days(10_000))
            .expect("timestamp válido")
            .timestamp() as usize;

        let claims = Claims { sub: user_id, exp: expiration };

        let secret = env::var("SECRET_KEY").unwrap_or_else(|_| {
            eprintln!("⚠ Advertencia: SECRET_KEY no está definido.");
            "secret".to_string()
        });

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_ref()),
        )
        .map_err(|e| {
            eprintln!("❌ Error generando JWT: {}", e);
            actix_web::error::ErrorInternalServerError("Error al generar el token")
        })?;

        return Ok(HttpResponse::Ok().json(ApiResponse {
            success: true,
            message: None,
            data: Some(json!({ "token": token, "user_id": user_id })),
        }));
    }

    println!("❌ Usuario o contraseña incorrectos");
    Err(actix_web::error::ErrorUnauthorized("Credenciales inválidas"))
}

#[post("/logout")]
async fn logout() -> Json<serde_json::Value> {
    Json(json!({
        "success": true,
        "message": "Sesión cerrada exitosamente"
    }))
}


#[derive(Deserialize)]
struct SearchQuery {
    query: String,
}

#[get("/search_users")]
async fn search_users(
    pool: web::Data<Pool>,
    req: HttpRequest,
    query: web::Query<SearchQuery>
) -> Result<HttpResponse, Error> {
    // Extraer el token del encabezado Authorization
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header_value) => {
            let token_str = header_value.to_str().unwrap_or("");
            if token_str.starts_with("Bearer ") {
                token_str.trim_start_matches("Bearer ").trim().to_string()
            } else {
                return Ok(HttpResponse::Unauthorized().json(SearchResponse {
                    success: false,
                    message: Some("Token no proporcionado".to_string()),
                    users: None,
                }));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(SearchResponse {
                success: false,
                message: Some("Token no proporcionado".to_string()),
                users: None,
            }));
        }
    };

    // Validar el token JWT
    let secret = env::var("SECRET_KEY").unwrap_or_else(|_| "secret".to_string());
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    if let Err(err) = decode::<Claims>(&token, &decoding_key, &validation) {
        println!("Error al decodificar token: {:?}", err);
        return Ok(HttpResponse::Unauthorized().json(SearchResponse {
            success: false,
            message: Some("Token inválido o expirado".to_string()),
            users: None,
        }));
    }

    // Realizar la consulta a la base de datos usando el parámetro 'query'
    let client = pool.get().await.map_err(|_| actix_web::error::ErrorInternalServerError("Error de conexión a DB"))?;
    let search_term = format!("%{}%", query.query);
    let rows = client.query(
        "SELECT nombre, user_id, categoria, imagep FROM datos WHERE nombre ILIKE $1",
        &[&search_term]
    )
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("Error en la consulta SQL"))?;

    let users: Vec<User> = rows.into_iter().map(|row: Row| {
        User {
            nombre: row.get("nombre"),
            user_id: row.get("user_id"),
            categoria: row.get("categoria"),
            imagep: row.get("imagep"),
        }
    }).collect();

    let response = SearchResponse {
        success: true,
        message: Some("Usuarios encontrados".to_string()),
        users: Some(users),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[get("/recibir_post")]
async fn recibir_post(pool: web::Data<Pool>) -> Result<HttpResponse, Error> {
    let client = connect_to_postgresql(pool).await?;
    let rows = client
        .query(
            "SELECT datos.imagep, datos.nombre, publicacion.id, publicacion.titulo, 
                   publicacion.descripcion, publicacion.imagen, publicacion.fecha, 
                   publicacion.like_count, publicacion.user_id
            FROM datos
            JOIN publicacion ON datos.user_id = publicacion.user_id
            WHERE datos.categoria = 'Restaurante'
            ORDER BY publicacion.id DESC",
            &[],
        )
        .await
        .map_err(|e| {
            eprintln!("Error en consulta SQL: {}", e);
            actix_web::error::ErrorInternalServerError("Error interno del servidor")
        })?;

    let publicaciones: Vec<Publicacion> = rows
        .iter()
        .map(|row| Publicacion {
            imagep: row.get(0),
            nombre: row.get(1),
            id: row.get(2),
            titulo: row.get(3),
            descripcion: row.get(4),
            imagen: row.get(5),
            fecha: row.get(6),
            like_count: row.get(7),
            user_id: row.get(8),
        })
        .collect();

    Ok(HttpResponse::Ok().json(ApiResponse {
        success: true,
        message: Some("Datos recuperados exitosamente".to_string()),
        data: Some(publicaciones),
    }))
}


#[get("/recibir_perfil")]
async fn recibir_perfil(pool: web::Data<Pool>, req: actix_web::HttpRequest) -> Result<HttpResponse, Error> {
    // Extraer el token del header "Authorization"
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header_value) => {
            let token_str = header_value.to_str().unwrap_or("").to_string();
            if token_str.starts_with("Bearer ") {
                // Remover el prefijo "Bearer " y quitar saltos de línea y espacios adicionales
                token_str.trim_start_matches("Bearer ")
                    .replace("\n", "")
                    .replace(" ", "")
            } else {
                return Ok(HttpResponse::Unauthorized().json(PerfilResponse {
                    success: false,
                    message: "Token no proporcionado".to_string(),
                    imagep: None,
                    image_fondo: None,
                    nombre: None,
                    categoria: None,
                }));
            }
        },
        None => {
            return Ok(HttpResponse::Unauthorized().json(PerfilResponse {
                success: false,
                message: "Token no proporcionado".to_string(),
                imagep: None,
                image_fondo: None,
                nombre: None,
                categoria: None,
            }));
        }
    };

    // Usar la misma clave secreta que se usó al firmar el token
    let secret = env::var("SECRET_KEY").unwrap_or_else(|_| "secret".to_string());
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);

    // Decodificar el token JWT
    let token_data = decode::<Claims>(&token, &decoding_key, &validation);
    let user_id = match token_data {
        Ok(data) => data.claims.sub, // Se espera que 'sub' contenga el user_id
        Err(err) => {
            // Dependiendo del error, devolvemos mensaje "Token expirado" o "Token inválido"
            if err.to_string().contains("ExpiredSignature") {
                return Ok(HttpResponse::Unauthorized().json(PerfilResponse {
                    success: false,
                    message: "Token expirado".to_string(),
                    imagep: None,
                    image_fondo: None,
                    nombre: None,
                    categoria: None,
                }));
            } else {
                println!("Error al decodificar token: {:?}", err);
                return Ok(HttpResponse::Unauthorized().json(PerfilResponse {
                    success: false,
                    message: "Token inválido".to_string(),
                    imagep: None,
                    image_fondo: None,
                    nombre: None,
                    categoria: None,
                }));
            }
        }
    };

    // Imprimir el user_id para depuración
    println!("user_id: {}", user_id);

    // Conectar a la base de datos y ejecutar la consulta
    let client = pool.get().await.map_err(|_| actix_web::error::ErrorInternalServerError("Error de conexión con la base de datos"))?;
    let row: Option<Row> = client.query_opt(
        "SELECT imagep, image_fondo, nombre, categoria FROM datos WHERE user_id = $1",
        &[&user_id]
    ).await.map_err(|_| actix_web::error::ErrorInternalServerError("Error en la consulta SQL"))?;

    // Armar la respuesta según si se encontraron datos o no
    if let Some(row) = row {
        let response = PerfilResponse {
            success: true,
            message: "Datos recuperados exitosamente".to_string(),
            imagep: row.get(0),
            image_fondo: row.get(1),
            nombre: row.get(2),
            categoria: row.get(3),
        };

        Ok(HttpResponse::Ok().json(response))
    } else {
        Ok(HttpResponse::Ok().json(PerfilResponse {
            success: false,
            message: "No se encontraron datos para el usuario actual".to_string(),
            imagep: None,
            image_fondo: None,
            nombre: None,
            categoria: None,
        }))
    }
}



#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("¡Hola desde Rust!")
}

fn create_pool() -> Pool {
    let mut config = Config::new();
    config.dbname = Some(env::var("DB_NAME").unwrap_or_else(|_| "postgres".to_string()));
    config.user = Some(env::var("DB_USER").unwrap_or_else(|_| "postgres".to_string()));
    config.password = Some(env::var("DB_PASSWORD").unwrap_or_else(|_| "password".to_string()));
    config.host = Some(env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string()));

    config.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });

    config.create_pool(Some(Runtime::Tokio1), NoTls).expect("Error creando el pool de conexiones")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();  // Carga las variables de entorno desde .env
    let pool = create_pool();

    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                origin == "http://localhost:8100" || origin == "cordova://localhost"
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::CONTENT_TYPE])
            .supports_credentials();

        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(pool.clone()))
            .service(login)
            .service(logout)
            .service(recibir_post)
            .service(recibir_perfil)
            .service(search_users)
            .service(index)
    })
    .bind(format!("0.0.0.0:{}", port))? // Usa el puerto de la variable de entorno
    .run()
    .await
}
