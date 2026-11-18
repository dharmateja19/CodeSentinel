const password = "mySecretPassword123";

// Dangerous dynamic execution
eval(userInput);

// Potential DOM-based XSS
document.getElementById("output").innerHTML = location.search;

// Potential command injection
exec(`ls ${userInput}`);

// Potential SQL injection
db.query(`SELECT * FROM users WHERE id = ${userId}`);