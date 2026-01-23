# HELP.md

This document provides common setup instructions, troubleshooting steps, and development tips for the **Redis Token Management (Spring Boot + JWT)** project.

---

## 📌 Project Overview

This project implements:
- JWT authentication (Access + Refresh tokens)
- Redis-backed token storage
- Token blacklisting on logout
- Refresh token validation with scope checking
- Spring Security 6 (stateless)

---

## 🚀 Getting Started

### Prerequisites
- Java 17+
- Maven 3.8+
- Redis (local or Docker)
- Git

---

## 🧪 Running Redis

### Option 1: Run Redis with Docker
```bash
docker run -d \
  --name redis-auth \
  -p 6379:6379 \
  redis:7
