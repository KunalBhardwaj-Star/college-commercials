require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");
const methodOverride = require("method-override");
const { v4: uuidv4 } = require("uuid");

const app = express();

// Middleware
app.use(methodOverride("_method"));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: "mysecretkey", // Change this for better security
    resave: false,
    saveUninitialized: true
}));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "/views"));

// Database Connection
const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// Home Route - Show User Count
app.get("/", (req, res) => {
    let q = `SELECT * FROM user`;

    connection.query(q, (err, users) => {
        if (err) {
            console.error(err);
            return res.send("Database error");
        }
        res.render("home.ejs", { users });  // Pass users to home.ejs
    });
});


// Show All Users
app.get("/user", (req, res) => {
    let q = `SELECT * FROM user`;
    connection.query(q, (err, users) => {
        if (err) {
            console.error(err);
            return res.send("Database error");
        }
        res.render("showusers.ejs", { users });
    });
});

// Show New User Form
app.get("/user/new", (req, res) => {
    res.render("new.ejs");
});

// Add New User (with Hashed Password)

app.post("/user/new/", async (req, res) => {
    let { username, email, password } = req.body;
    let id = uuidv4();
    
    // Hash the password before saving to the database
    let hashedPassword = await bcrypt.hash(password, 10);

    let q3 = `INSERT INTO user (id, username, email, password) VALUES (?, ?, ?, ?)`;
    connection.query(q3, [id, username, email, hashedPassword], (err) => {
        if (err) {
            console.error(err);
            return res.send("Error occurred while adding user.");
        }
        res.redirect("/user");
    });
});

app.get('/new', (req, res) => {
    res.render('new');
});


// Show Edit Form
app.get("/user/:id/edit", (req, res) => {
    let { id } = req.params;
    let q = `SELECT * FROM user WHERE id = ?`;

    connection.query(q, [id], (err, result) => {
        if (err || result.length === 0) {
            console.error(err);
            return res.send("User not found");
        }
        res.render("edit.ejs", { user: result[0] });
    });
});

// Update User (Only Username)
app.patch("/user/:id", async (req, res) => {
    let { id } = req.params;
    let { password, username } = req.body;

    let q = `SELECT * FROM user WHERE id = ?`;
    connection.query(q, [id], async (err, result) => {
        if (err || result.length === 0) {
            console.error(err);
            return res.send("User not found");
        }

        let user = result[0];
        let isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.send("Incorrect password");
        }

        let q2 = `UPDATE user SET username = ? WHERE id = ?`;
        connection.query(q2, [username, id], (err) => {
            if (err) {
                console.error(err);
                return res.send("Error updating user");
            }
            res.redirect("/user");
        });
    });
});

// Show Delete Confirmation
app.get("/user/:id/delete", (req, res) => {
    let { id } = req.params;
    console.log("Delete Request for User ID:", id);  // Debugging

    let q = `SELECT * FROM user WHERE id = ?`;

    connection.query(q, [id], (err, result) => {
        if (err) {
            console.error("Database Error:", err);
            return res.send("Database error.");
        }

        if (result.length === 0) {
            console.log("User not found in database.");
            return res.send("User not found!");
        }

        let user = result[0];
        res.render("delete.ejs", { user });
    });
});



app.delete("/user/:id", async (req, res) => {
    let { id } = req.params;
    let { password } = req.body;

    let q = `SELECT * FROM user WHERE id = ?`;
    connection.query(q, [id], async (err, result) => {
        if (err || result.length === 0) {
            console.error("User not found in database.");
            return res.send("User not found!");
        }

        let user = result[0];

        // Compare hashed password
        let isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.send("Incorrect password!");
        }

        let q2 = `DELETE FROM user WHERE id = ?`;
        connection.query(q2, [id], (err) => {
            if (err) {
                console.error("Error deleting user:", err);
                return res.send("Error deleting user.");
            }
            console.log("User deleted successfully!");
            res.redirect("/user");
        });
    });
});

// Handle Sign-in

app.post("/user/sign-in", async (req, res) => {
    let { username, password } = req.body;

    let q = `SELECT * FROM user WHERE LOWER(username) = LOWER(?)`;
    connection.query(q, [username], async (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.send("Error in database.");
        }

        if (result.length === 0) {
            return res.send("User not found! Please check your username.");
        }

        let user = result[0];

        // Compare hashed password
        let isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.send("Incorrect password!");
        }

        res.redirect("/user"); // Redirect after successful login
    });
});


// Sign-in Page
app.get("/user/sign-in", (req, res) => {
    res.render("sign-in.ejs", { user: {} });  // Pass an empty user object
});


// Start Server
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
    console.log(`Server is listening at port ${PORT}`);
});
