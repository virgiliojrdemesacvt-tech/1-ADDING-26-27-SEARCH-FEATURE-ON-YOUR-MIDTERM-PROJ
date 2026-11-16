<?php
/* ---------- XSS DEMO SWITCH ----------
   false = PROTECTED (normal use; keep it false when submitting/deploying)
   true  = VULNERABLE (ONLY for the XSS attack screenshots: no input cleaning, no output escaping, no CSP) */
define('XSS_DEMO_MODE', false);

/* ---------- HELPER ---------- */

// Reads an id from the URL (?customer_id=3). Sends the user home if it is missing.
function requireId($key) {
    if (!isset($_GET[$key]) || !ctype_digit((string)$_GET[$key])) {
        $inCore = basename(dirname($_SERVER['SCRIPT_NAME'])) === 'core';
        header("Location: " . ($inCore ? "../index.php" : "index.php"));
        exit;
    }
    return (int)$_GET[$key];
}

// XSS DEFENSE 1 - OUTPUT ESCAPING: turns < > & " ' into harmless text entities.
// Every value printed in a page must go through e().
function e($value) {
    if (XSS_DEMO_MODE) { return (string)$value; }   // demo only: unprotected output
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// XSS DEFENSE 2 - INPUT SANITIZING: trim, remove HTML/PHP tags and control characters before saving.
function clean($value) {
    $value = trim((string)$value);
    if (XSS_DEMO_MODE) { return $value; }            // demo only: unprotected input
    $value = strip_tags($value);
    return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $value);
}

// Reads a POST field and cleans it in one step: post('firstName')
function post($key) {
    return clean($_POST[$key] ?? '');
}

// PASSWORD POLICY: at least 8 characters with a number, an UPPERCASE and a lowercase letter.
// Returns an error message, or null when the password is acceptable.
function validatePasswordStrength($pw) {
    if (strlen($pw) < 8)             { return 'Password must be at least 8 characters long.'; }
    if (!preg_match('/[a-z]/', $pw)) { return 'Password must contain at least one lowercase letter.'; }
    if (!preg_match('/[A-Z]/', $pw)) { return 'Password must contain at least one UPPERCASE letter.'; }
    if (!preg_match('/[0-9]/', $pw)) { return 'Password must contain at least one number.'; }
    return null;
}

// Shows "—" when nobody is recorded (old records, or the user was removed)
function who($name) {
    return ($name === null || trim($name) === '') ? '—' : $name;
}

/* ---------- USERS (people who log in) ---------- */

function userExists($pdo, $username, $email) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?");
    $stmt->execute([$username, $email]);
    return $stmt->fetchColumn() > 0;
}

function insertUser($pdo, $first_name, $last_name, $address, $age, $contact_no, $email, $username, $password, $role = 'editor') {
    $sql = "INSERT INTO users (first_name, last_name, address, age, contact_no, email, username, password_hash, role)
            VALUES (?,?,?,?,?,?,?,?,?)";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$first_name, $last_name, $address, $age, $contact_no, $email, $username,
                           password_hash($password, PASSWORD_DEFAULT), $role]);
}

function getUserByUsername($pdo, $username) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    return $stmt->fetch();
}

/* ---------- CUSTOMERS (the "one" side) ---------- */

// Reused by the SELECT queries: also fetch the NAMES of the users who added / last updated a row
function whoJoin($alias) {
    return "LEFT JOIN users ua ON {$alias}.added_by = ua.user_id
            LEFT JOIN users uu ON {$alias}.last_updated_by = uu.user_id";
}
function insertCustomer($pdo, $username, $first_name, $last_name, $date_of_birth, $license_number, $user_id) {
    $sql = "INSERT INTO customers (username, first_name, last_name, date_of_birth, license_number, added_by, last_updated_by)
            VALUES (?,?,?,?,?,?,?)";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$username, $first_name, $last_name, $date_of_birth, $license_number, $user_id, $user_id]);
}

function getAllCustomers($pdo, $q = '') {
    $sql = "SELECT customers.*,
                   CONCAT(ua.first_name, ' ', ua.last_name) AS added_by_name,
                   CONCAT(uu.first_name, ' ', uu.last_name) AS updated_by_name
            FROM customers " . whoJoin('customers');
    $params = [];
    if ($q !== '') {
        $sql .= " WHERE (customers.username LIKE ? OR customers.first_name LIKE ?
                         OR customers.last_name LIKE ? OR customers.license_number LIKE ?)";
        $like = '%' . $q . '%';
        $params = [$like, $like, $like, $like];
    }
    $sql .= " ORDER BY customers.customer_id DESC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function getCustomerByID($pdo, $customer_id) {
    $sql = "SELECT customers.*,
                   CONCAT(ua.first_name, ' ', ua.last_name) AS added_by_name,
                   CONCAT(uu.first_name, ' ', uu.last_name) AS updated_by_name
            FROM customers " . whoJoin('customers') . "
            WHERE customers.customer_id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$customer_id]);
    return $stmt->fetch();
}

function updateCustomer($pdo, $first_name, $last_name, $date_of_birth, $license_number, $customer_id, $user_id) {
    $sql = "UPDATE customers
            SET first_name = ?, last_name = ?, date_of_birth = ?, license_number = ?,
                last_updated_by = ?, last_updated = NOW()
            WHERE customer_id = ?";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$first_name, $last_name, $date_of_birth, $license_number, $user_id, $customer_id]);
}

function deleteCustomer($pdo, $customer_id) {
    // Delete the child rows (rentals) first, then the parent
    $stmt = $pdo->prepare("DELETE FROM rentals WHERE customer_id = ?");
    if ($stmt->execute([$customer_id])) {
        $pdo->prepare("DELETE FROM customer_accounts WHERE customer_id = ?")->execute([$customer_id]);
        $stmt2 = $pdo->prepare("DELETE FROM customers WHERE customer_id = ?");
        return $stmt2->execute([$customer_id]);
    }
    return false;
}

/* ---------- RENTALS (the "many" side) ---------- */

function getRentalsByCustomer($pdo, $customer_id, $q = '') {
    $sql = "SELECT rentals.rental_id, rentals.car_model, rentals.rental_days,
                   rentals.date_added, rentals.last_updated, rentals.last_updated_by,
                   CONCAT(customers.first_name, ' ', customers.last_name) AS customer_name,
                   CONCAT(ua.first_name, ' ', ua.last_name) AS added_by_name,
                   CONCAT(uu.first_name, ' ', uu.last_name) AS updated_by_name
            FROM rentals
            JOIN customers ON rentals.customer_id = customers.customer_id
            " . whoJoin('rentals') . "
            WHERE rentals.customer_id = ?";
    $params = [$customer_id];
    if ($q !== '') {
        $sql .= " AND (rentals.car_model LIKE ? OR rentals.rental_days LIKE ?)";
        $like = '%' . $q . '%';
        $params[] = $like;
        $params[] = $like;
    }
    $sql .= " ORDER BY rentals.rental_id DESC";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function insertRental($pdo, $car_model, $rental_days, $customer_id, $user_id) {
    $sql = "INSERT INTO rentals (car_model, rental_days, customer_id, added_by, last_updated_by) VALUES (?,?,?,?,?)";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$car_model, $rental_days, $customer_id, $user_id, $user_id]);
}

function getRentalByID($pdo, $rental_id) {
    $sql = "SELECT rentals.rental_id, rentals.car_model, rentals.rental_days,
                   rentals.date_added, rentals.last_updated,
                   CONCAT(customers.first_name, ' ', customers.last_name) AS customer_name,
                   CONCAT(ua.first_name, ' ', ua.last_name) AS added_by_name,
                   CONCAT(uu.first_name, ' ', uu.last_name) AS updated_by_name
            FROM rentals
            JOIN customers ON rentals.customer_id = customers.customer_id
            " . whoJoin('rentals') . "
            WHERE rentals.rental_id = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$rental_id]);
    return $stmt->fetch();
}

function updateRental($pdo, $car_model, $rental_days, $rental_id, $user_id) {
    $sql = "UPDATE rentals SET car_model = ?, rental_days = ?, last_updated_by = ?, last_updated = NOW()
            WHERE rental_id = ?";
    $stmt = $pdo->prepare($sql);
    return $stmt->execute([$car_model, $rental_days, $user_id, $rental_id]);
}

function deleteRental($pdo, $rental_id) {
    $stmt = $pdo->prepare("DELETE FROM rentals WHERE rental_id = ?");
    return $stmt->execute([$rental_id]);
}


/* ================= ROLES, LOGS, CUSTOMER ACCOUNTS ================= */

function staffRoles() { return ['admin', 'moderator', 'editor']; }

// The cars customers can book (name => icon)
function carFleet() {
    return [
        'Toyota Vios'             => "\u{1F697}",
        'Honda City'              => "\u{1F697}",
        'Hyundai Accent'          => "\u{1F698}",
        'Mitsubishi Montero Sport'=> "\u{1F699}",
        'Toyota Fortuner'         => "\u{1F699}",
        'Ford Ranger'             => "\u{1F6FB}",
        'Nissan Navara'           => "\u{1F6FB}",
        'Toyota Hiace'            => "\u{1F690}",
    ];
}

function countRows($pdo, $table) {
    $allowed = ['customers', 'rentals', 'users', 'customer_accounts', 'activity_logs'];
    if (!in_array($table, $allowed, true)) { return 0; }
    return (int)$pdo->query("SELECT COUNT(*) FROM `{$table}`")->fetchColumn();
}

/* ---------- activity logs ---------- */

function logActivity($pdo, $actorType, $actorId, $actorName, $role, $action, $details = '') {
    try {
        $stmt = $pdo->prepare("INSERT INTO activity_logs (actor_type, actor_id, actor_name, role, action, details, ip_address)
                               VALUES (?,?,?,?,?,?,?)");
        $stmt->execute([$actorType, $actorId, substr((string)$actorName, 0, 120), $role, $action,
                        substr(clean($details), 0, 255), $_SERVER['REMOTE_ADDR'] ?? null]);
    } catch (PDOException $e) {
        // logging must never break the system
    }
}

function getLogs($pdo, $action = '', $limit = 300) {
    $sql = "SELECT * FROM activity_logs";
    $params = [];
    if ($action !== '') { $sql .= " WHERE action = ?"; $params[] = $action; }
    $sql .= " ORDER BY log_id DESC LIMIT " . (int)$limit;
    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function getLogActions($pdo) {
    return $pdo->query("SELECT DISTINCT action FROM activity_logs ORDER BY action")->fetchAll(PDO::FETCH_COLUMN);
}

// CSS colour class for a log action
function actClass($action) {
    foreach (['DELETE', 'CANCEL', 'FAILED'] as $w) { if (strpos($action, $w) !== false) { return 'act-bad'; } }
    foreach (['ADD', 'BOOK', 'REGISTER'] as $w)     { if (strpos($action, $w) !== false) { return 'act-good'; } }
    foreach (['EDIT', 'ROLE'] as $w)                { if (strpos($action, $w) !== false) { return 'act-warn'; } }
    return 'act-info';
}

/* ---------- staff user management (admin) ---------- */

function getAllUsers($pdo) {
    return $pdo->query("SELECT user_id, first_name, last_name, username, email, role, date_registered
                        FROM users ORDER BY user_id")->fetchAll();
}

function getUserById($pdo, $id) {
    $stmt = $pdo->prepare("SELECT user_id, username, role FROM users WHERE user_id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function updateUserRole($pdo, $id, $role) {
    $stmt = $pdo->prepare("UPDATE users SET role = ? WHERE user_id = ?");
    return $stmt->execute([$role, $id]);
}

/* ---------- CUSTOMER accounts (separate login from staff) ---------- */

function customerAccountExists($pdo, $username, $email) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM customer_accounts WHERE username = ? OR email = ?");
    $stmt->execute([$username, $email]);
    return $stmt->fetchColumn() > 0;
}

// Creates the customer record AND the login account together. Returns the new customer_id or false.
function insertCustomerAccount($pdo, $first, $last, $dob, $license, $email, $username, $password) {
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("INSERT INTO customers (username, first_name, last_name, date_of_birth, license_number)
                               VALUES (?,?,?,?,?)");
        $stmt->execute([$username, $first, $last, $dob, $license]);
        $customerId = (int)$pdo->lastInsertId();
        $stmt = $pdo->prepare("INSERT INTO customer_accounts (customer_id, email, username, password_hash) VALUES (?,?,?,?)");
        $stmt->execute([$customerId, $email, $username, password_hash($password, PASSWORD_DEFAULT)]);
        $pdo->commit();
        return $customerId;
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) { $pdo->rollBack(); }
        return false;
    }
}

function getCustomerAccountByUsername($pdo, $username) {
    $stmt = $pdo->prepare("SELECT ca.*, c.first_name, c.last_name
                           FROM customer_accounts ca JOIN customers c ON c.customer_id = ca.customer_id
                           WHERE ca.username = ? LIMIT 1");
    $stmt->execute([$username]);
    return $stmt->fetch();
}

function rentalBelongsTo($pdo, $rental_id, $customer_id) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM rentals WHERE rental_id = ? AND customer_id = ?");
    $stmt->execute([$rental_id, $customer_id]);
    return $stmt->fetchColumn() > 0;
}
