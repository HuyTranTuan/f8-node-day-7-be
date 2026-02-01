CREATE DATABASE  IF NOT EXISTS `node_day_7` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `node_day_7`;
-- MySQL dump 10.13  Distrib 8.0.44, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: node_day_7
-- ------------------------------------------------------
-- Server version	8.0.44

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `queues`
--

DROP TABLE IF EXISTS `queues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `queues` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `type` varchar(255) COLLATE utf8mb4_unicode_520_ci DEFAULT NULL,
  `payload` text CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci,
  `status` varchar(255) COLLATE utf8mb4_unicode_520_ci DEFAULT 'pending',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `queues`
--

LOCK TABLES `queues` WRITE;
/*!40000 ALTER TABLE `queues` DISABLE KEYS */;
INSERT INTO `queues` VALUES (16,'sendVerifyEmail','{\"id\":52,\"username\":\"yáuossss\",\"email\":\"trantuanhuyltv@gmail.com\"}','completed','2026-02-01 17:45:36','2026-02-01 20:21:31'),(20,'sendPasswordChangeEmail','{\"id\":41,\"email\":\"trantuanhuyltv@gmail.com\"}','completed','2026-02-01 20:31:22','2026-02-01 20:31:26');
/*!40000 ALTER TABLE `queues` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `revoked_tokens`
--

DROP TABLE IF EXISTS `revoked_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `revoked_tokens`
--

LOCK TABLES `revoked_tokens` WRITE;
/*!40000 ALTER TABLE `revoked_tokens` DISABLE KEYS */;
INSERT INTO `revoked_tokens` VALUES (7,'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjQxLCJleHAiOjE3Njk3MjEzNjgxMDEsImlhdCI6MTc2OTcxNzc2OH0.4JcUtsa-qhQs5U1POoVSzrn3_QeGm7Wd3pOSXBkyj1o','2026-01-29 20:16:31','2026-01-29 20:16:31','2026-01-29 20:16:31',41);
/*!40000 ALTER TABLE `revoked_tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tasks`
--

DROP TABLE IF EXISTS `tasks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tasks`
--

LOCK TABLES `tasks` WRITE;
/*!40000 ALTER TABLE `tasks` DISABLE KEYS */;
INSERT INTO `tasks` VALUES (1,42,'di choiw','di choi den 10h toi ve',0,'2026-01-29 16:33:10','2026-01-29 16:33:10',NULL),(2,42,'di choiw','di choi den 10h toi ve',0,'2026-01-29 16:33:35','2026-01-29 16:44:00','2026-01-29 16:33:35'),(3,42,'di choiw','di choi den 10h toi ve',0,'2026-01-29 16:33:36','2026-01-29 16:33:36',NULL),(4,41,'đi boiw','di boi di toi ve',0,'2026-01-29 16:36:07','2026-01-29 17:43:54','2026-01-29 17:43:54'),(5,41,'di choiw','di choi den 10h toi ve',0,'2026-01-29 16:36:09','2026-01-29 16:44:13','2026-01-29 16:36:09'),(6,41,'đi chơi','di choi di toi ve',0,'2026-01-29 17:09:09','2026-01-29 17:09:09',NULL);
/*!40000 ALTER TABLE `tasks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
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
) ENGINE=InnoDB AUTO_INCREMENT=53 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (39,'huytrantuan12','trantuanhuy1@gmail.com','$2b$10$9PS5XBHM4WUvozpkoTpr/OcqPLfLO4AmmtftCcrThcNe20oc48o5e','user','Y4T5e0gB2Eyt0SgpzoxD6KlxKGnZZTVG',NULL,'2026-01-29 15:14:46','2026-01-29 18:21:27',NULL,'2026-02-05 18:21:28'),(41,'huytrantuan2','trantuanhuy2@gmail.com','$2b$10$Q193bsNawfWClNFMUZRQfuogs/BuUnZEZmcEKgtBNKBEAK.PgBDS2','user','keV99w7JdljVLTptxBvTpOj6ibw9wAjT',NULL,'2026-01-29 15:27:47','2026-02-01 20:53:03',NULL,'2026-02-08 20:15:26'),(42,'huytrantuan3','trantuanhuy3@gmail.com','$2b$10$mz5mrCcaw6k6AN21eFySfezBKvwtxCiX7yuhYni4QygThNs9GXCq6','user','o37i2A8f47SuQpe9wXCZRzHahmAWBsQO',NULL,'2026-01-29 15:39:09','2026-01-29 18:21:03',NULL,'2026-02-05 18:21:04'),(52,'yáuossss','trantuanhuyl@gmail.com','$2b$10$YTgDM3mcz2UG0wC.9Gtc5.27TzWgyGg3wTSeSh1yQUsoFPvJMxKw2','user','9s3ASfhCkcMBCNPpvzHHJa7ko4RccYoW','2026-02-01 18:50:18','2026-01-30 18:13:19','2026-02-01 20:53:03',NULL,'2026-02-06 18:13:19');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-02-02  3:54:53
