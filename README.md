<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" /></a>
</p>

## Flujo de Uso - API NestJS

### 1\. Registro de Usuario

#### Endpoint

```bash
POST /auth/register
```

El usuario se registra proporcionando un **email** y una **contraseña**.

#### Respuesta

```json
{
"message": "📧 Registration successful. Verification email sent.",
"user": {
  "id": 1,
  "email": "user@example.com",
  "roles": \["user"\],
  "emailVerified": false
  }
}
```

### 2\. Verificación de Email

#### Endpoint

```bash
GET /auth/verify-email
```

El usuario verifica su email a través del token de verificación enviado por correo electrónico.

#### Respuesta

```json
{
  "message": "📧 Email successfully verified"
}
```

## 3\. Inicio de Sesión

#### Endpoint

```bash
POST /auth/login
```

El usuario proporciona su **email** y **contraseña** para iniciar sesión.

#### Respuesta

```json
{
  "message": "🔐 Login successful",
  "access_token": "jwt-token-aqui"
}
```

## 4\. Solicitud de Restablecimiento de Contraseña

#### Endpoint

```bash
POST /auth/request-password-reset
```

El usuario puede solicitar un restablecimiento de contraseña proporcionando su **email**.

#### Respuesta

```json
{
  "message": "✉️ Password reset email sent"
}
```

## 5\. Restablecimiento de Contraseña

#### Endpoint

```bash
POST /auth/reset-password
```

El usuario restablece su contraseña utilizando el **emailVerificationToken** y la nueva **contraseña**.

#### Respuesta

```json
{
  "message": "🔑 Password changed successfully"
}
```

## 6\. Activar Autenticación de Doble Factor (2FA)

#### Endpoint

```bash
GET /auth/2fa/generate
```

El usuario genera un código QR para configurar la autenticación de doble factor (2FA).

#### Respuesta

El backend enviará una imagen PNG con el código QR que el usuario debe escanear con su aplicación 2FA.

## 7\. Verificar el Código de 2FA

#### Endpoint

```bash
POST /auth/2fa/verify
```

El usuario verifica el código de 2FA enviado por su aplicación de autenticación.

#### Respuesta

```json
{
  "message": "✅ 2FA verified",
  "access_token": "jwt-token-aqui"
}
```

## 8\. Habilitar o Deshabilitar el 2FA

#### Endpoint

```bash
POST /auth/2fa/enable
```

El usuario puede habilitar o deshabilitar la autenticación de doble factor enviando un booleano **enable**.

#### Respuesta

```json
{
  "message": "🔒 2FA enabled successfully" // o "🔓 2FA disabled successfully"
}
```

## 9\. Actualizar Perfil de Usuario

#### Endpoint

```bash
PATCH /auth/user/profile
```

El usuario puede actualizar su **nombre** o **email**.

#### Respuesta

```json
{
  "message": "👤 Profile updated successfully"
}
```

## 10\. Acceso de Administrador

#### Endpoint

```bash
GET /auth/admin
```

Los usuarios con el rol de **admin** pueden acceder a este endpoint.

#### Respuesta

```json
{
  "message": "🔐 Admin access granted"
}
```
