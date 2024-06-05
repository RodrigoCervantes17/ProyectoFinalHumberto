const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../lib/db.js');
const userMiddleware = require('../middleware/users.js');

// http://localhost:3000/api/sign-up
router.post('/sign-up', userMiddleware.validateRegister, (req, res, next) => {
  db.query(
    'SELECT id FROM users WHERE LOWER(username) = LOWER(?)',
    [req.body.username],
    (err, result) => {
      if (result && result.length) {
        // error
        return res.status(409).send({
          message: 'This username is already in use!',
        });
      } else {
        // username not in use
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).send({
              message: err,
            });
          } else {
            db.query(
              'INSERT INTO users (username, password, registered, admin) VALUES (?, ?, now(), FALSE);',
              [req.body.username, hash],
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    message: err,
                  });
                }
                return res.status(201).send({
                  message: 'Registered!',
                });
              }
            );
          }
        });
      }
    }
  );
});

// http://localhost:3000/api/sign-up/admin
router.post('/sign-upAdmin', userMiddleware.validateRegister, (req, res, next) => {
  db.query(
    'SELECT id FROM users WHERE LOWER(username) = LOWER(?)',
    [req.body.username],
    (err, result) => {
      if (result && result.length) {
        // error
        return res.status(409).send({
          message: 'This username is already in use!',
        });
      } else {
        // username not in use
        bcrypt.hash(req.body.password, 10, (err, hash) => {
          if (err) {
            return res.status(500).send({
              message: err,
            });
          } else {
            db.query(
              'INSERT INTO users (username, password, registered, admin) VALUES (?, ?, now(), TRUE);', //ESPACIO ADMIN EN VERDADERO
              [req.body.username, hash],
              (err, result) => {
                if (err) {
                  return res.status(400).send({
                    message: err,
                  });
                }
                return res.status(201).send({
                  message: 'Registered!',
                });
              }
            );
          }
        });
      }
    }
  );
});

// http://localhost:3000/api/login
router.post('/login', (req, res, next) => {
  db.query(
    `SELECT * FROM users WHERE username = ?;`,
    [req.body.username],
    (err, result) => {
      if (err) {
        return res.status(400).send({
          message: err,
        });
      }
      if (!result.length) {
        return res.status(400).send({
          message: 'Username or password incorrect!',
        });
      }

      bcrypt.compare(
        req.body.password,
        result[0]['password'],
        (bErr, bResult) => {
          if (bErr) {
            return res.status(400).send({
              message: 'Username or password incorrect!',
            });
          }
          if (bResult) {
            // password match
            const token = jwt.sign(
              {
                username: result[0].username,
                userId: result[0].id,
              },
              process.env.SECRET_KEY,
              { expiresIn: '7d' }
            );
            db.query(`UPDATE users SET last_login = now() WHERE id = ?;`, [
              result[0].id,
            ]);
            return res.status(200).send({
              message: 'Logged in!',
              token,
              user: result[0],
            });
          }
          return res.status(400).send({
            message: 'Username or password incorrect!',
          });
        }
      );
    }
  );
});

// http://localhost:3000/api/secret-route
// ACABO DE PONER ADMIN AQUI EN PRUEBA
router.get('/secret-route', userMiddleware.isLoggedIn, (req, res, next) => { 
  console.log(req.userData);
  res.send('This is secret content!');
});




//http://localhost:3000/api/users
router.get('/users', userMiddleware.isLoggedIn, (req, res, next) => { 
  
  db.query(
    "SELECT * FROM users;",
    (err, rows, fields) =>
    {
        if (err)
        {
            res.json(err)
        }
        else
        {
            res.json(rows)
        }
    }
);

});
// http://localhost:3000/api/productos
router.get('/productos', userMiddleware.isLoggedIn, (req, res, next) => { 
  
  db.query(
    "SELECT * FROM productos;",
    (err, rows, fields) =>
    {
        if (err)
        {
            res.json(err)
        }
        else
        {
            res.json(rows)
        }
    }
);

});

// http://localhost:3000/api/agregarProductos
router.post('/agregarProductos', userMiddleware.isLoggedIn, (req,res,next) => {
  db.query(
    "INSERT INTO productos (nombre, cantidad, costo) VALUES (?, ?, ?);",
    [req.body.nombre, req.body.cantidad, req.body.costo],
    (err, rows, fields) =>
    {
        if (err)
        {
            res.json(err)
        }
        else
        {
            res.json(rows)
        }
    }
);
},
)

// http://localhost:3000/api/buscarProductos
router.post('/buscarProductos', userMiddleware.isLoggedIn, (req, res) => {
  db.query(
      'SELECT * FROM productos where nombre like "?";',
      [`%${req.body.nombre}%`],
      (err, rows, fields) => {
          if (err)
              res.json(err)
          else
              res.json(rows)
      }
  )
}),


//modificarProductos
router.post('/modificarProductos', userMiddleware.isLoggedIn, (req,res,next) => {
  {
    db.query(
        `UPDATE productos SET ${req.body.nombre} = ? WHERE id = ?;`,
        [req.body.valor, req.body.id],
        (err, rows, fields) =>
        {
            if (err)
            {
                res.json(err)
            }
            else
            {
                res.json(rows)
            }
        }
    )
}}
)





module.exports = router;