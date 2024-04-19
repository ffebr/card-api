// db.js

const mysql = require('mysql2');

const dbConnection = mysql.createConnection({
    host: '127.0.0.1',
    port: '3307',
    user: 'root',
    password: '0000',
    database: 'hakaton'
});

dbConnection.connect((err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err);
        return;
    }
    console.log('Подключение к базе данных успешно установлено');
});

module.exports = dbConnection;