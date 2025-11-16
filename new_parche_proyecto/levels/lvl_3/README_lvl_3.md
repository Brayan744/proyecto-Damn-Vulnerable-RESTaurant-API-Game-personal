
# Level 3: Broken Function Level Authorization (BFLA) - Privilege Escalation

## 📌 Inicio Rápido

### Prerequisitos
Asegúrate de tener activado tu entorno virtual de Python:

```bash
source venv/bin/activate
```

### Comandos de Prueba

#### 1️⃣ Ejecutar exploit para ver la vulnerabilidad
```bash
python3 new_parche_proyecto/levels/lvl_3/script/exploit_lvl3.py
```

#### 2️⃣ Aplicar parche de seguridad
```bash
sudo cp new_parche_proyecto/levels/lvl_3/fix/update_user_role_service.py app/apis/users/services/update_user_role_service.py
```

#### 3️⃣ Verificar que la vulnerabilidad fue corregida
```bash
python3 new_parche_proyecto/levels/lvl_3/script/exploit_lvl3.py
```

#### 4️⃣ Revertir parche (opcional)
```bash
sudo cp new_parche_proyecto/levels/lvl_3/unpatch/update_user_role_service.py app/apis/users/services/update_user_role_service.py
```

---

## 📋 Clasificación OWASP
**API5:2023 - Broken Function Level Authorization (BFLA)**

## 🎯 Descripción de la Vulnerabilidad

El endpoint `PUT /users/update_role` permite a cualquier usuario autenticado cambiar el rol de **cualquier otro usuario**, incluyendo el suyo propio, sin validar si el usuario que realiza la petición tiene los permisos necesarios para otorgar o escalar roles. Esto resulta en una escalada de privilegios donde un usuario con rol `Customer` puede asignarse a sí mismo (o a otros) roles de mayor jerarquía como `Employee` o `Chef`.

### El Problema

La función `update_user_role` carece de una validación de autorización por roles adecuada. No verifica:

-   **Quién está realizando la petición**: Si el `current_user` tiene un rol que le permite modificar roles de otros usuarios.
-   **Permisos de escalada**: Si el `current_user` tiene permiso para asignarse a sí mismo un rol superior (`Employee` o `Chef`).
-   **Rol objetivo**: Si el rol `user.role` que se intenta asignar está permitido para el `current_user`.

El código vulnerable es el siguiente:

```python
@router.put("/users/update_role", response_model=UserRoleUpdate)
async def update_user_role(
    user: UserRoleUpdate,
    current_user: Annotated[models.User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    db_user = update_user(db, user.username, user)
    return current_user
```

## 🔓 Cómo se Explota

### Paso 1: Crear una Cuenta de Atacante (Customer)
El atacante registra una cuenta normal, que por defecto recibe el rol `Customer`. Por ejemplo, `David`.

```bash
POST /register
Content-Type: application/json

{
  "username": "David",
  "password": "pass123",
  "phone_number": "555-4321",
  "first_name": "Attack",
  "last_name": "User"
}
```

### Paso 2: Autenticación del Atacante
Obtener un token de acceso para el usuario `David` (que tiene el rol `Customer`).

```bash
POST /token
Content-Type: application/x-www-form-urlencoded

username=David&password=pass123
```

### Paso 3: Escalar Privilegios
Usando el token del usuario `David` (Customer), el atacante realiza una petición `PUT` al endpoint `/users/update_role`, indicando que quiere cambiar el rol del usuario `David` a `Employee`.

```bash
PUT /users/update_role
Authorization: Bearer {token_david}
Content-Type: application/json

{
  "username": "David",
  "role": "Employee"
}
```

**Respuesta:**
```
HTTP/1.1 200 OK
```
El usuario `David` (antes `Customer`) ahora tiene el rol `Employee`.

### Paso 4: Verificar la Escalada
El atacante puede verificar su nuevo rol consultando su perfil o intentando acceder a un endpoint restringido solo para `Employees`.

```bash
GET /profile
Authorization: Bearer {token_david}
```
**Respuesta (ejemplo):**
```json
{
  "username": "David",
  "phone_number": "555-4321",
  "first_name": "Attack",
  "last_name": "User",
  "role": "Employee" 
}
```

## 🛡️ Cómo Solucionarlo

### Solución: Implementar RolesBasedAuthChecker y Validaciones Específicas

**Código Vulnerable:**
```python
@router.put("/users/update_role", response_model=UserRoleUpdate)
async def update_user_role(
    user: UserRoleUpdate,
    current_user: Annotated[models.User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    db_user = update_user(db, user.username, user)
    return current_user
```

**Código Seguro:**
```python
@router.put("/users/update_role", response_model=UserRoleUpdate)
async def update_user_role(
    user: UserRoleUpdate,
    current_user: Annotated[models.User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    # Solución 1: Asegurar que solo roles autorizados puedan acceder a esta función
    # Solo "Employee" o "Chef" pueden usar este endpoint para cambiar roles.
    # Los Customers no pueden acceder.
    auth=Depends(RolesBasedAuthChecker([UserRole.EMPLOYEE, UserRole.CHEF])), 
):
    # Solución 2: Validar que un Customer no pueda actualizar su propio rol
    if current_user.role == models.UserRole.CUSTOMER.value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Customer no puede actualizar su rol",
        )

    # Solución 3: Restringir la asignación del rol CHIEF a solo otros CHIEF
    # Un "Employee" no puede asignar el rol "CHIEF". Solo otro "CHIEF" puede hacerlo.
    if user.role == models.UserRole.CHEF.value and current_user.role != models.UserRole.CHEF.value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Only Chef is authorized to add Chef role!",
        )

    db_user = update_user(db, user.username, user)
    return current_user
```

### Principios de Seguridad Aplicados

1.  **Least Privilege**: Los usuarios solo tienen los permisos mínimos necesarios para realizar sus tareas. Un `Customer` no debería poder modificar roles.
2.  **Role-Based Access Control (RBAC)**: Validar los roles en todas las funciones sensibles y administrativas.
3.  **Defense in Depth**: Múltiples capas de validación (autenticación + autorización de función + autorización de rol específico).
4.  **Secure by Default**: Las funciones de cambio de roles deben ser restrictivas por diseño.

## 🔍 Escenarios de Ataque

### Escenario 1: Sabotaje Interno o Externo
Un atacante (o un empleado descontento con cuenta de `Customer`) escala sus privilegios a `Employee` o `Chef` y luego usa esas nuevas capacidades para eliminar elementos del menú (API5:2023 del Nivel 1) o acceder a información sensible.

### Escenario 2: Creación de Cuentas Falsas con Roles Elevados
Un atacante crea múltiples cuentas con el rol `Customer` y las escala a `Employee` para inundar el sistema con personal falso, dificultando la gestión y auditoría.

### Escenario 3: Acceso a Funciones Restringidas
Una vez escalado a `Employee`, el atacante puede acceder a otros endpoints que estaban restringidos, lo que podría llevar a más vulnerabilidades (como SSRF en el Nivel 4) o filtración de datos.

### Escenario 4: Auditoría y Pruebas de Penetración
Un auditor de seguridad o un pentester demuestra la capacidad de un usuario con privilegios bajos para escalar su rol, lo que evidencia una falla crítica en el control de acceso.

## 🔬 Prueba de Concepto

Ejecutar el exploit:
```bash
python new_parche_proyecto/levels/lvl_3/script/exploit_lvl3.py
```

El script:
1.  Creará un usuario `lvl3_test` con el rol `Customer`.
2.  Obtendrá un token de autenticación para `lvl3_test`.
3.  Verificará el rol inicial del usuario (`Customer`).
4.  Intentará escalar el rol de `lvl3_test` a `Employee` usando el endpoint `PUT /users/update_role`.
5.  Verificará el rol final del usuario.
6.  Mostrará si la escalada fue exitosa (vulnerable) o bloqueada (protegida).

## 📚 Referencias

-   OWASP API Security Top 10 2023: API5:2023
-   CWE-285: Improper Authorization
-   CWE-863: Incorrect Authorization




