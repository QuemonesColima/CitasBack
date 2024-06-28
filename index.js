const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const swaggerUi = require("swagger-ui-express");
const swaggerSpec = require("./swaggerConfig");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const app = express();
const port = 3000;
// Configurar CORS
app.use(cors());
// Configurar body-parser para manejar solicitudes más grandes
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));
// Configurar ruta para servir archivos estáticos
app.use("/uploads", express.static("uploads"));
// Conectar a la base de datos SQLite
const db = new sqlite3.Database("mi-base-de-datos.db");
// Configuración de Multer para almacenamiento
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Carpeta donde se guardarán los archivos
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Nombre único para cada archivo
  },
});

const upload = multer({ storage: storage });

// Crear tablas (dueños y citas)
db.serialize(() => {
  db.run("ALTER TABLE users ADD COLUMN profile_image TEXT", [], function (err) {
    if (err) {
      if (err.message.includes("duplicate column name")) {
        console.log("La columna profile_image ya existe en la tabla users.");
      } else {
        console.error(err.message);
      }
    }
  });

  db.run(
    "ALTER TABLE owners ADD COLUMN profile_image TEXT",
    [],
    function (err) {
      if (err) {
        if (err.message.includes("duplicate column name")) {
          console.log("La columna profile_image ya existe en la tabla owners.");
        } else {
          console.error(err.message);
        }
      }
    }
  );
});
db.serialize(() => {
  // Incluye aquí los comandos CREATE TABLE para cada una de tus tablas
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, phone_number TEXT, password TEXT, client_name TEXT, profile_image TEXT)"
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS owners (id INTEGER PRIMARY KEY, phone_number TEXT, password TEXT, client_name TEXT, profile_image TEXT)"
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS businesses (id INTEGER PRIMARY KEY, owner_id INTEGER, name TEXT, location TEXT, contact_number TEXT)"
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY, owner_id INTEGER, client_name TEXT, date TEXT, time TEXT, business_id INTEGER REFERENCES businesses(id))"
  );
});

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
// Middleware para parsear el cuerpo de las solicitudes como JSON
app.use(express.json());

// Middleware para hash de contraseñas usando bcrypt
const hashPasswordMiddleware = async (req, res, next) => {
  const { password } = req.body;
  if (password) {
    const hashedPassword = await bcrypt.hash(password, 10);
    req.body.password = hashedPassword;
  }
  next();
};

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Registrar un nuevo usuario (dueño o cliente)
 *     description: Endpoint para registrar un nuevo usuario en la aplicación.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               phone_number:
 *                 type: string
 *                 description: Número de teléfono del usuario.
 *               password:
 *                 type: string
 *                 description: Contraseña del usuario.
 *               is_owner:
 *                 type: boolean
 *                 description: Indica si el usuario es un dueño.
 *               client_name:
 *                 type: string
 *                 description: Nombre del cliente (requerido si is_owner es falso).
 *             required:
 *               - phone_number
 *               - password
 *               - is_owner
 *     responses:
 *       201:
 *         description: Usuario registrado exitosamente.
 *         content:
 *           application/json:
 *             example:
 *               id: 1
 *               phone_number: "123456789"
 *               is_owner: true
 *               client_name: "Nombre del Cliente"
 *       400:
 *         description: Campos incompletos o inválidos en la solicitud.
 *         content:
 *           application/json:
 *             example:
 *               error: "Campos incompletos"
 *       500:
 *         description: Error interno del servidor.
 *         content:
 *           application/json:
 *             example:
 *               error: "Error interno del servidor"
 */
// Endpoint de registro
/* app.post("/register", hashPasswordMiddleware, (req, res) => {
  const { phone_number, password, is_owner, client_name, profile_image } =
    req.body;

  if (
    !phone_number ||
    !password ||
    is_owner === undefined ||
    (is_owner === false && !client_name)
  ) {
    return res.status(400).json({ error: "Campos incompletos" });
  }

  const tableName = is_owner ? "owners" : "users";

  // Verificar si el phone_number ya existe
  db.get(
    `SELECT * FROM ${tableName} WHERE phone_number = ?`,
    [phone_number],
    (err, row) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Error interno del servidor" });
      }
      if (row) {
        return res
          .status(400)
          .json({ error: "Usuario con ese num de tel ya existe" });
      }

      // Agregar el usuario a la base de datos
      const sql = is_owner
        ? `INSERT INTO ${tableName} (phone_number, password, profile_image) VALUES (?, ?, ?)`
        : `INSERT INTO ${tableName} (phone_number, password, client_name, profile_image) VALUES (?, ?, ?, ?)`;

      const params = is_owner
        ? [phone_number, password, profile_image]
        : [phone_number, password, client_name, profile_image];

      db.run(sql, params, function (err) {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: "Error interno del servidor" });
        }
        // Éxito al registrar el usuario
        res.status(201).json({
          id: this.lastID,
          phone_number,
          is_owner,
          client_name,
          profile_image,
        });
      });
    }
  );
}); */

app.post(
  "/register",
  upload.single("profile_image"),
  hashPasswordMiddleware,
  (req, res) => {
    const { phone_number, password, client_name } = req.body;
    let { is_owner } = req.body;
    const profile_image = req.file ? req.file.filename : null;

    console.log("Datos recibidos:", {
      phone_number,
      password,
      is_owner,
      client_name,
      profile_image,
    });

    // Convertir is_owner a booleano
    is_owner = is_owner === "true" || is_owner === true;

    if (
      !phone_number ||
      !password ||
      is_owner === undefined ||
      (is_owner === false && !client_name)
    ) {
      return res.status(400).json({ error: "Campos incompletos" });
    }

    const tableName = is_owner ? "owners" : "users";

    // Verificar si el phone_number ya existe
    db.get(
      `SELECT * FROM ${tableName} WHERE phone_number = ?`,
      [phone_number],
      (err, row) => {
        if (err) {
          console.error(
            "Error al verificar el número de teléfono:",
            err.message
          );
          return res.status(500).json({ error: "Error interno del servidor" });
        }
        if (row) {
          console.log("Usuario con ese número de teléfono ya existe:", row);
          return res
            .status(400)
            .json({ error: "Usuario con ese número de teléfono ya existe" });
        }

        // Agregar el usuario a la base de datos
        const sql = is_owner
          ? `INSERT INTO ${tableName} (phone_number, password, profile_image) VALUES (?, ?, ?)`
          : `INSERT INTO ${tableName} (phone_number, password, client_name, profile_image) VALUES (?, ?, ?, ?)`;

        const params = is_owner
          ? [phone_number, password, profile_image]
          : [phone_number, password, client_name, profile_image];

        console.log("SQL para insertar usuario:", sql);
        console.log("Parámetros:", params);

        db.run(sql, params, function (err) {
          if (err) {
            console.error("Error al insertar el usuario:", err.message);
            return res
              .status(500)
              .json({ error: "Error interno del servidor" });
          }
          console.log(`Usuario añadido con ID: ${this.lastID}`);
          // Éxito al registrar el usuario
          res.status(201).json({
            id: this.lastID,
            phone_number,
            is_owner,
            client_name,
            profile_image,
          });
        });
      }
    );
  }
);

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Iniciar sesión de usuario
 *     description: Endpoint para autenticar a un usuario y obtener un token de sesión.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               phone_number:
 *                 type: string
 *                 description: Número de teléfono del usuario.
 *               password:
 *                 type: string
 *                 description: Contraseña del usuario.
 *             required:
 *               - phone_number
 *               - password
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso.
 *         content:
 *           application/json:
 *             example:
 *               success: true
 *               is_owner: true
 *       401:
 *         description: Credenciales inválidas.
 *         content:
 *           application/json:
 *             example:
 *               error: "Credenciales inválidas"
 *       400:
 *         description: Campos incompletos o inválidos en la solicitud.
 *         content:
 *           application/json:
 *             example:
 *               error: "Campos incompletos"
 */
app.post("/login", async (req, res) => {
  const { phone_number, password } = req.body;
  console.log("Datos recibidos:", { phone_number, password });

  if (!phone_number || !password) {
    return res.status(400).json({ error: "Campos incompletos" });
  }

  try {
    console.log("Consultando en la tabla owners");
    const ownerResult = await queryUser("owners", phone_number, password);
    console.log("Resultado owners:", ownerResult);

    console.log("Consultando en la tabla users");
    const userResult = await queryUser("users", phone_number, password);
    console.log("Resultado users:", userResult);

    if (ownerResult || userResult) {
      const user = ownerResult || userResult;
      console.log("Usuario encontrado:", user);
      res.json({
        success: true,
        is_owner: !!ownerResult,
        id: user.id,
        phone_number: user.phone_number,
        client_name: user.client_name,
        profile_image: user.profile_image,
      });
    } else {
      console.log("Credenciales inválidas");
      res.status(401).json({ error: "Credenciales inválidas" });
    }
  } catch (error) {
    console.error("Error en el servidor:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});
// Endpoint para crear un negocio
app.post("/create-business", (req, res) => {
  const { owner_id, name, location, contact_number } = req.body;

  if (!owner_id || !name || !location || !contact_number) {
    return res.status(400).json({ error: "Campos incompletos" });
  }

  // Verificar si el dueño existe
  db.get("SELECT * FROM owners WHERE id = ?", [owner_id], (err, owner) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: "Error interno del servidor" });
    }

    if (!owner) {
      return res.status(404).json({ error: "Dueño no encontrado" });
    }

    // Agregar el negocio a la base de datos
    const sql =
      "INSERT INTO businesses (owner_id, name, location, contact_number) VALUES (?, ?, ?, ?)";
    const params = [owner_id, name, location, contact_number];

    db.run(sql, params, function (err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Error interno del servidor" });
      }

      // Éxito al crear el negocio
      res
        .status(201)
        .json({ id: this.lastID, owner_id, name, location, contact_number });
    });
  });
});

// Endpoint para agendar una cita
app.post("/schedule-appointment", (req, res) => {
  const { owner_id, client_name, date, time, business_id } = req.body;

  if (!owner_id || !client_name || !date || !time || !business_id) {
    return res.status(400).json({ error: "Campos incompletos" });
  }

  // Verificar si el dueño y el negocio existen
  db.get("SELECT * FROM owners WHERE id = ?", [owner_id], (err, owner) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: "Error interno del servidor" });
    }

    if (!owner) {
      return res.status(404).json({ error: "Dueño no encontrado" });
    }

    db.get(
      "SELECT * FROM businesses WHERE id = ? AND owner_id = ?",
      [business_id, owner_id],
      (err, business) => {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: "Error interno del servidor" });
        }

        if (!business) {
          return res
            .status(404)
            .json({ error: "Negocio no encontrado o no pertenece al dueño" });
        }

        // Agregar la cita a la base de datos
        const sql =
          "INSERT INTO appointments (owner_id, client_name, date, time, business_id) VALUES (?, ?, ?, ?, ?)";
        const params = [owner_id, client_name, date, time, business_id];

        db.run(sql, params, function (err) {
          if (err) {
            console.error(err.message);
            return res
              .status(500)
              .json({ error: "Error interno del servidor" });
          }

          // Éxito al agendar la cita
          res.status(201).json({
            id: this.lastID,
            owner_id,
            client_name,
            date,
            time,
            business_id,
          });
        });
      }
    );
  });
});

// Endpoint para obtener citas programadas de un cliente
app.get("/appointments/:clientId", (req, res) => {
  const clientId = req.params.clientId;

  // Verificar si el usuario existe y es un cliente
  db.get(
    "SELECT * FROM users WHERE id = ? AND is_owner = 0",
    [clientId],
    (err, user) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Error interno del servidor" });
      }

      if (!user) {
        return res
          .status(404)
          .json({ error: "Usuario no encontrado o no es un cliente" });
      }

      // Obtener citas programadas del cliente
      db.all(
        "SELECT * FROM appointments WHERE owner_id = ? ORDER BY date, time",
        [clientId],
        (err, appointments) => {
          if (err) {
            console.error(err.message);
            return res
              .status(500)
              .json({ error: "Error interno del servidor" });
          }

          // Éxito al obtener las citas
          res.json({ client_name: user.client_name, appointments });
        }
      );
    }
  );
});

// Función auxiliar para consultar un usuario en una tabla específica

const queryUser = (table, phone_number, password) => {
  console.log("TABLA A CONSULTAR", table);
  return new Promise((resolve, reject) => {
    const sql = `SELECT * FROM ${table} WHERE phone_number = ?`;
    db.get(sql, [phone_number], async (err, row) => {
      if (err) {
        return reject(err);
      }
      if (row) {
        const match = await bcrypt.compare(password, row.password);
        if (match) {
          return resolve(row);
        } else {
          return resolve(null);
        }
      } else {
        return resolve(null);
      }
    });
  });
};
// Middleware para parsear el cuerpo de las solicitudes como JSON
app.use(express.json());

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Obtiene la lista de usuarios
 *     description: Endpoint para obtener todos los usuarios registrados.
 *     responses:
 *       200:
 *         description: Respuesta exitosa. Devuelve la lista de usuarios.
 *         content:
 *           application/json:
 *             example:
 *               - id: 1
 *                 phone_number: "123456789"
 *                 password: "hashedpassword"
 *                 is_owner: 0
 *               - id: 2
 *                 phone_number: "987654321"
 *                 password: "hashedpassword"
 *                 is_owner: 1
 *       500:
 *         description: Error interno del servidor.
 *         content:
 *           application/json:
 *             example:
 *               error: "Error interno del servidor"
 */
app.get("/users", (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.error(err.message);
      res.status(500).json({ error: "Error interno del servidor" });
    } else {
      res.json(rows);
    }
  });
});

// Asegúrate de que el directorio de 'uploads' existe
const fs = require("fs");
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor iniciado en http://localhost:${port}`);
});
