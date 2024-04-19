// app.js

const express = require('express');
const authRouter = require('./authRouter'); // импорт роутера

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // Для разбора тела запроса в формате JSON

// Подключение роутера для аутентификации
app.use('/api/auth', authRouter);

// Другие роутеры вашего приложения могут быть подключены здесь...

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});