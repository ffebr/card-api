const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const dbConnection = require('./db');
const moment = require('moment');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // Для разбора тела запроса в формате JSON
app.use(cors());
// Функция для создания JWT токена
function generateToken(user) {
    return jwt.sign({ id: user.id, username: user.username }, '224455', { expiresIn: '1h' });
}

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
                // Обновление поля last_login
                const currentDatetime = new Date().toISOString().slice(0, 19).replace('T', ' ');
                dbConnection.query('UPDATE users SET last_login = ? WHERE id = ?', [currentDatetime, user.id], (err) => {
                    if (err) {
                        console.error('Ошибка обновления last_login:', err);
                        return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
                    }

                    // Создание JWT токена с user_id
                    const token = generateToken({ id: user.id, username: user.username });
                    res.json({ token, user_id: user.id });
                });
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
app.post('/api/createCard', async (req, res) => {
    try {
        const { user_id } = req.body;

        // Получаем роль пользователя из базы данных
        dbConnection.query('SELECT role FROM users WHERE id = ?', [user_id], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            const userRole = results[0].role;

            // Проверяем, равна ли роль 'norole'
            if (userRole === 'norole') {
                return res.status(403).json({ error: 'Пользователь не имеет права создавать карту' });
            }

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
                dbConnection.query('SELECT MAX(last_card_number) AS lastCardNumber FROM cards', (err, result) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }

                    if (result.length > 0 && result[0].lastCardNumber) {
                        lastCardNumber = result[0].lastCardNumber + 1;
                    }

                    // Генерируем дату создания
                    const creationDate = new Date().toISOString().slice(0, 19).replace('T', ' ');

                    // Вставляем новую карту в базу данных
                    dbConnection.query('INSERT INTO cards (user_id, last_card_number, creation_date) VALUES (?, ?, ?)', [user_id, lastCardNumber, creationDate], (err, result) => {
                        if (err) {
                            return res.status(500).json({ error: err.message });
                        }
                        res.status(201).json({ message: 'Карта успешно создана', card_number: lastCardNumber });
                    });
                });
            });
        });
    } catch (error) {
        console.error('Ошибка создания карты:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});


//получение информации о user
app.get('/api/user/:user_id', async (req, res) => {
    try {
        const userId = req.params.user_id;

        // Получаем данные пользователя из базы данных
        dbConnection.query('SELECT first_name, last_name, patro, email, role, polic, birth FROM users WHERE id = ?', [userId], (err, userResults) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (userResults.length === 0) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            const userData = userResults[0];

            // Проверяем, существует ли карта у пользователя
            dbConnection.query('SELECT series_card, last_card_number, balance FROM cards WHERE user_id = ?', [userId], (err, cardResults) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                if (cardResults.length > 0) {
                    const cardData = cardResults[0];
                    userData.card = cardData;
                }

                res.json(userData);
            });
        });
    } catch (error) {
        console.error('Ошибка получения данных пользователя:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});


app.get('/api/getActions', (req, res) => {
    try {
        const today = new Date().toISOString().slice(0, 10); // Получаем сегодняшнюю дату в формате "YYYY-MM-DD"

        // Запрос к базе данных для получения всех действий, у которых end_date больше сегодняшней даты
        dbConnection.query(
            `SELECT actions.*, partners.name AS partner_name FROM actions
            INNER JOIN partners ON actions.partner_id = partners.id
            WHERE end_date > ?`,
            [today],
            (err, results) => {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }

                res.json(results);
            }
        );
    } catch (error) {
        console.error('Ошибка получения данных о действиях:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});


// app.js

// ...

// Редактирование данных пользователя
app.put('/api/useredit/:user_id', async (req, res) => {
    try {
        const userId = req.params.user_id;
        const { first_name, patro, last_name, birth_date, polic } = req.body;

        // Проверяем, существует ли пользователь с указанным user_id
        dbConnection.query('SELECT * FROM users WHERE id = ?', [userId], async (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            // Обновляем данные пользователя
            dbConnection.query('UPDATE users SET first_name = ?, patro = ?, last_name = ?, birth = ?, polic = ? WHERE id = ?', 
                [first_name, patro, last_name, birth_date, polic, userId], 
                (err, result) => {
                    if (err) {
                        return res.status(500).json({ error: err.message });
                    }
                    res.json({ message: 'Данные пользователя успешно обновлены' });
                }
            );
        });
    } catch (error) {
        console.error('Ошибка при обновлении данных пользователя:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// app.js

// Редактирование данных пользователя



app.get('/api/events', (req, res) => {
    try {
        // Получение текущей даты в формате YYYY-MM-DD
        const currentDate = moment().format('YYYY-MM-DD');

        // SQL-запрос для получения данных о событиях с датой больше текущего дня
        const sqlQuery = `SELECT events.name, events.event_desc, events.advantages, events.date, events.location, partners.name AS partner_name 
                          FROM events 
                          INNER JOIN partners ON events.partner_id = partners.id
                          WHERE events.date > ?`;

        // Выполнение SQL-запроса с использованием текущей даты в качестве параметра
        dbConnection.query(sqlQuery, [currentDate], (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            // Отправка данных о событиях в формате JSON
            res.json(results);
        });
    } catch (error) {
        console.error('Ошибка при получении данных о событиях:', error);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
