CREATE DATABASE IF NOT EXISTS booking_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

USE booking_db;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL,
  role ENUM('user','admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role)
VALUES ('admin', '1234', 'admin@email.com', 'admin');

CREATE TABLE bookings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  type VARCHAR(50) NOT NULL,
  date DATE NOT NULL,
  time TIME NOT NULL,
  end_time TIME NOT NULL,
  purpose TEXT NOT NULL,
  equipment VARCHAR(255),
  status ENUM('pending','approved','rejected') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
