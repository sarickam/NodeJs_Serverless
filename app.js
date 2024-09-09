const serverless = require("serverless-http");
const express = require("express");
const fs = require("fs");
const path = require("path");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fileUpload = require("express-fileupload");
const { authenticateToken, registerEmployee, loginEmployee, refreshAccessToken, logoutEmployee } = require("./auth");
const db = require("./db");
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Middleware to handle file uploads
app.use(fileUpload({
  createParentPath: true,
  limits: { fileSize: 2 * 1024 * 1024 },
  abortOnLimit: true,
  safeFileNames: true,
  preserveExtension: true
}));

// Ensure the 'uploads' directory exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Joi schema for validating employee data
const employeeSchema = Joi.object({
  id: Joi.number().integer().optional(),
  first_name: Joi.string().trim(),
  last_name: Joi.string().trim(),
  email: Joi.string().email().trim().optional(),
  phone_number: Joi.string().trim().optional(),
  date_of_birth: Joi.date().iso().optional(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  address: Joi.string().trim().optional(),
  city: Joi.string().trim().optional(),
  state: Joi.string().trim().optional(),
  country: Joi.string().trim().optional(),
  zip_code: Joi.string().trim().optional(),
  department: Joi.string().trim().optional(),
  job_title: Joi.string().trim().optional(),
  salary: Joi.number().min(0).optional(),
  hire_date: Joi.date().iso().optional(),
  profile_picture: Joi.string().optional(),
  username: Joi.string().trim().optional(),
  password: Joi.string().trim().optional(),
});

// Middleware to validate request data using Joi
const validateEmployee = (req, res, next) => {
  const { error } = employeeSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({ errors: error.details.map((err) => err.message) });
  }
  next();
};

// Route to register a new user
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  // Generate a 4-digit random number
  const userId = Math.floor(1000 + Math.random() * 9000); // Generates a random number between 1000 and 9999

  registerEmployee(username, password, userId, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(201).json({ message: "User registered successfully" });
  });
});


// Route to login and get JWT token
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  loginEmployee(username, password, (err, tokens) => {
    if (err) {
      return res.status(401).json({ message: err.message });
    }
    res.json(tokens);
  });
});


// Route to refresh access token using refresh token
app.post("/refresh-token", refreshAccessToken);

// Route to log out and invalidate the refresh token
app.post("/logout", logoutEmployee);


// Route to handle updating an employee with file upload
app.put("/employees", authenticateToken, validateEmployee, async (req, res) => {
  const {
    id, // Take id from the request body
    first_name,
    last_name,
    email,
    phone_number,
    date_of_birth,
    gender,
    address,
    city,
    state,
    country,
    zip_code,
    department,
    job_title,
    salary,
    hire_date
  } = req.body;

  if (!id) {
    return res.status(400).json({ message: "ID is required to update employee data" });
  }

  let profile_picture = null;

  if (req.files && req.files.profile_picture) {
    const file = req.files.profile_picture;
    profile_picture = path.join(__dirname, "uploads", file.name);

    try {
      await new Promise((resolve, reject) => {
        file.mv(profile_picture, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  const sql = `UPDATE Emp SET
    first_name = ?, last_name = ?, email = ?, phone_number = ?, date_of_birth = ?, gender = ?,
    address = ?, city = ?, state = ?, country = ?, zip_code = ?, department = ?, job_title = ?, salary = ?, hire_date = ?,
    profile_picture = COALESCE(?, profile_picture)
    WHERE id = ?`; // Use `id` from the request body

  console.log("Updating employee with ID:", id);
  console.log("SQL Query:", sql);
  console.log("Query Parameters:", [
    first_name,
    last_name,
    email,
    phone_number,
    date_of_birth,
    gender,
    address,
    city,
    state,
    country,
    zip_code,
    department,
    job_title,
    salary,
    hire_date,
    profile_picture,
    id
  ]);

  db.query(
    sql,
    [
      first_name,
      last_name,
      email,
      phone_number,
      date_of_birth,
      gender,
      address,
      city,
      state,
      country,
      zip_code,
      department,
      job_title,
      salary,
      hire_date,
      profile_picture,
      id // Use the id passed in the request body
    ],
    (err, result) => {
      if (err) {
        console.error("Database error:", err.message);
        return res.status(500).json({ error: err.message });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Employee not found" });
      }
      res.json({ message: "Employee updated successfully", profile_picture });
    }
  );
});


// Route to handle partially updating an employee's data
app.patch("/employees", authenticateToken, validateEmployee, (req, res) => {
  const updates = req.body;
  const { id } = updates; // Get id from the request body

  if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
    return res.status(400).json({ message: "Invalid data format" });
  }

  delete updates.id; // Remove `id` from the updates, as we already have it

  let sql = "UPDATE Emp SET ";
  const updateValues = [];
  let profile_picture = null; // Define profile_picture here

  for (const key in updates) {
    if (Object.prototype.hasOwnProperty.call(updates, key)) {
      sql += `${key} = ?, `;
      updateValues.push(updates[key]);
    }
  }

  if (req.files && req.files.profile_picture) {
    const file = req.files.profile_picture;
    const uploadPath = path.join(__dirname, "uploads", file.name);
    profile_picture = path.join("uploads", file.name); // Assign path to profile_picture
    sql += `profile_picture = ?, `;
    updateValues.push(profile_picture);
    file.mv(uploadPath, (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
    });
  }

  if (updateValues.length === 0) {
    return res.status(400).json({ message: "No valid fields to update" });
  }

  sql = sql.slice(0, -2); // Remove the trailing comma and space
  sql += " WHERE id = ?";
  updateValues.push(id); // Use the id passed in the request body

  db.query(sql, updateValues, (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Employee not found" });
    }
    res.json({ message: "Employee updated successfully", profile_picture });
  });
});

// Route to handle deleting the authenticated employee
app.delete("/employees", authenticateToken, (req, res) => {
  const { id } = req.user; // Get employee ID from the token payload

  if (!id) {
    return res.status(400).json({ message: "Employee ID is required" });
  }

  const sql = "DELETE FROM Emp WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Employee not found" });
    }
    res.json({ message: "Employee deleted successfully" });
  });
});

// Route to fetch employee details using authentication token
app.get("/employees", authenticateToken, (req, res) => {
  const { id } = req.user; // Get user ID from the token

  const sql = "SELECT * FROM Emp WHERE id = ?";

  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Employee not found" });
    }
    // Include full path in the response
    const employee = results[0];
    if (employee.profile_picture) {
      employee.profile_picture = path.join(__dirname, 'uploads', path.basename(employee.profile_picture));
    } else {
      // Handle case where profile_picture is null
      employee.profile_picture = null;
    }
    res.json(employee);
  });
});

// Route to get all employees - this may be restricted based on your needs
app.get("/all_employees", (req, res) => {
  const sql = "SELECT * FROM Emp";

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Serve the uploads folder statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.put("/admin/:id", async (req, res) => {
  const { id } = req.params;
  const {
    first_name,
    last_name,
    email,
    phone_number,
    date_of_birth,
    gender,
    address,
    city,
    state,
    country,
    zip_code,
    department,
    job_title,
    salary,
    hire_date
  } = req.body;

  let profile_picture = null;

  // Check if file exists
  if (req.files && req.files.profile_picture) {
    const file = req.files.profile_picture;

    // Get the original file extension
    const fileExtension = path.extname(file.name).toLowerCase();
    const validExtensions = ['.jpeg', '.jpg', '.png', '.gif'];

    // Check if file has a valid extension
    if (!validExtensions.includes(fileExtension)) {
      return res.status(400).json({ error: `Invalid file type: ${fileExtension}. Only .jpg, .jpeg, .png, and .gif are allowed.` });
    }

    // Generate a unique file name with correct extension
    const newFileName = `${Date.now()}-${Math.floor(Math.random() * 10000)}${fileExtension}`;
    const uploadPath = path.join(__dirname, 'uploads', newFileName);
    profile_picture = newFileName;

    try {
      // Save the file to the upload directory
      await new Promise((resolve, reject) => {
        file.mv(uploadPath, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    } catch (err) {
      return res.status(500).json({ error: `Failed to upload file: ${err.message}` });
    }
  }

  const sql = `UPDATE Emp SET
    first_name = ?, last_name = ?, email = ?, phone_number = ?, date_of_birth = ?, gender = ?,
    address = ?, city = ?, state = ?, country = ?, zip_code = ?, department = ?, job_title = ?, salary = ?, hire_date = ?,
    profile_picture = COALESCE(?, profile_picture)
    WHERE id = ?`;

  db.query(
    sql,
    [
      first_name,
      last_name,
      email,
      phone_number,
      date_of_birth,
      gender,
      address,
      city,
      state,
      country,
      zip_code,
      department,
      job_title,
      salary,
      hire_date,
      profile_picture,
      id
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Employee not found" });
      }
      res.json({
        message: "Employee updated successfully",
        profile_picture: profile_picture ? `/uploads/${profile_picture}` : null
      });
    }
  );
});


// Route to handle deleting an employee by ID with admin prefix
app.delete("/admin/:id", (req, res) => {
  const { id } = req.params; // Get ID from route parameters

  if (!id) {
    return res.status(400).json({ message: "Employee ID is required" });
  }

  const sql = "DELETE FROM Emp WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Employee not found" });
    }
    res.json({ message: "Employee deleted successfully" });
  });
});


module.exports = app;
