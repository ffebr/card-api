const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dbConnection = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // Для разбора тела запроса в формате JSON
app.use(cors());
// Функция для создания JWT токена
function generateToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, '224455', { expiresIn: '1h' });
}

// Регистрация нового пользователя
// Регистрация нового пользователя
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, first_name, patro, last_name } = req.body;
        if (!username || !password || !first_name || !last_name) {
            return res.status(400).json({ error: 'Необходимо указать имя пользователя, пароль, имя и фамилию' });
        }

        // Проверка, существует ли пользователь с таким именем
        dbConnection.query('SELECT * FROM users WHERE email = ?', [username], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
            }

            // Хэширование пароля
            const hashedPassword = await bcrypt.hash(password, 10);

            // Получение текущей даты и времени в формате MySQL
            const registrationDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

            // Вставка нового пользователя в базу данных
            dbConnection.query('INSERT INTO users (email, password, first_name, patro, last_name, registration_date) VALUES (?, ?, ?, ?, ?, ?)', [username, hashedPassword, first_name, patro, last_name, registrationDate], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.status(201).json({ message: 'Пользователь успешно зарегистрирован' });
            });
        });
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});


// Вход пользователя и создание JWT токена
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Необходимо указать имя пользователя и пароль' });
        }

        // Поиск пользователя в базе данных
        dbConnection.query('SELECT * FROM users WHERE email = ?', [username], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            // Проверка, найден ли пользователь
            if (results.length === 0) {
                return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }

            // Сравнение паролей
            const user = results[0];
            if (await bcrypt.compare(password, user.password)) {
                // Создание JWT токена
                const token = generateToken(user);
                res.json({ token });
            } else {
                res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Защищенный маршрут для проверки JWT токена
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'Это защищенный маршрут', user: req.user });
});

// Промежуточное ПО для проверки JWT токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется токен авторизации' });
    }

    jwt.verify(token, '224455', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Неверный токен авторизации' });
        }
        req.user = user;
        next();
    });
}


// Создание карты для пользователя
// Создание карты для пользователя
app.post('/api/createCard', async (req, res) => {
    try {
        const { user_id } = req.body;
        
        // Проверяем, существует ли карта для этого пользователя
        dbConnection.query('SELECT * FROM cards WHERE user_id = ?', [user_id], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length > 0) {
                return res.status(400).json({ error: 'У этого пользователя уже есть карта' });
            }

            // Получаем последний номер карты
            let lastCardNumber = 100000; // Начальное значение
            dbConnection.query('SELECT MAX(last_сard_number) AS lastCardNumber FROM cards', (err, result) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (result.length > 0 && result[0].lastCardNumber) {
                    lastCardNumber = result[0].lastCardNumber + 1;
                }

                // Генерируем дату создания
                const creationDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

                // Вставляем новую карту в базу данных
                dbConnection.query('INSERT INTO cards (user_id, card_number, creation_date) VALUES (?, ?, ?)', [user_id, lastCardNumber, creationDate], (err, result) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.status(201).json({ message: 'Карта успешно создана', card_number: lastCardNumber });
                });
            });
        });
    } catch (error) {
        console.error('Ошибка создания карты:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});





// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
