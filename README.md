### Clone the repository

git clone https://github.com/HuyTranTuan/f8-node-day-7-be.git

### Install dependencies

npm install

3.  Environment VariablesCreate a .env file in the root directory and add your database credentials:

    DB_HOST=localhost
    DB_USER=your_user
    DB_PASSWORD=your_password
    DB_NAME=your_db_name
    PORT=3000

4.  DB design:

## Database Schema

### Revoked Tokens Table

This table is used to store JTI (JWT IDs) or tokens that have been invalidated before their expiration date (e.g., during logout or token rotation).

```sql
CREATE TABLE `users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `password` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `role` enum('user','admin') DEFAULT 'user',
  `refresh_token` varchar(60) DEFAULT NULL,
  `verified_at` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` timestamp NULL DEFAULT NULL,
  `refresh_expires_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=43 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
```

```sql
CREATE TABLE `tasks` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `user_id` bigint unsigned DEFAULT NULL,
  `taskname` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `description` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `is_completed` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_task_user` (`user_id`),
  CONSTRAINT `fk_task_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
```

```sql
CREATE TABLE `revoked_tokens` (
  `id` tinyint NOT NULL AUTO_INCREMENT,
  `token` varchar(255) NOT NULL,
  `create_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `update_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `revoked_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `user_id` bigint unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_revokedtokens_users_user_id_idx` (`user_id`),
  CONSTRAINT `fk_revokedtokens_users_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

5.  Database SetupRun:

**===================**

\_ Register: POST /api/auth/register
{
"username": "youremail@gmail.com",
"email": "youremail@gmail.com",
"password": "yourpassword"
}

\_ Login: POST /api/auth/login
{
"email": "youremail@gmail.com",
"password": "yourpassword"
}

You will receive an accessToken, copy it and paste in to header "Authorization" with `Bearer {your_access_token}`

\_ Refresh token: POST /api/auth/refresh-token
{ "refresh_token": "refresh_token", }

\_ Logout: POST /api/auth/logout
{ }

**===================**

\_ Get all tasks: GET /api/tasks/
{ }

\_ Get one task: GET /api/tasks/:id
{ }

\_ Create task: POST /api/tasks/
{
"taskname": "taskname here",
"description": "description here",
}

\_ Update task: PUT /api/tasks/:id
{
"taskname": "taskname here",
"description": "description here",
}

\_ Completed task: PUT /api/tasks/:id/toggle-completed
{ }

\_ Detele task: DELETE /api/tasks/:id
{ }

**===================**

👨‍💻 AuthorHuy Tran TuanGitHub
