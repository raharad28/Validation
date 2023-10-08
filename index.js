const express = require('express');
const { body, validationResult } = require('express-validator');
const {param} = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const secretKey = 'president'; 

app.use(express.json());

let users = [];
let userIdCounter = 1;


app.post('/auth/register', [
  body('fullName').notEmpty().withMessage('Full name is required'),
  body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
  body('email').custom(value => {
    const existingUser = users.find(user => user.email === value);
    if (existingUser) {
      throw new Error('Email already registered');
    }
    return true;
  }),
  body('password').notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[\W]/).withMessage('Password must have at least 1 symbol'),
  body('bio').optional(),
  body('dob').optional().isDate().withMessage('Invalid date format (YYYY-MM-DD)'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation Error', detail: errors.array() });
  }

  const { fullName, email, password, bio, dob } = req.body;

  const hashedPassword = bcrypt.hashSync(password, 10);

  const user = {
    id: userIdCounter++,
    fullName,
    email,
    password: hashedPassword,
    bio,
    dob
  };

  users.push(user);

  res.status(201).json({ message: 'Registrasi success' });
});

app.post('/auth/login', [
    body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password is required')
      .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
      .matches(/[\W]/).withMessage('Password must have at least 1 symbol'),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation Error', detail: errors.array() });
    }
  
    const { email, password } = req.body;
  
    const user = users.find(user => user.email === email);
    if (!user) {
      return res.status(401).json({ message: 'Login Failed', reason: 'Email not found' });
    }
  
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Login Failed', reason: 'Password not valid' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: '1h' });
  
    res.status(200).json({ message: 'Success', data: { token } });
  });

  app.get('/users', (req, res) => {
    if (users.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    const userData = users.map(user => ({
      fullName: user.fullName,
      email: user.email,
      bio: user.bio,
      dob: user.dob
    }));
  
    res.status(200).json({ message: 'Success', data: userData });
  });
  
  app.get('/users/:userId', [
    param('userId').isNumeric().withMessage('User ID must be a number'),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation Error', detail: errors.array() });
    }
  
    const userId = parseInt(req.params.userId, 10);
    const user = users.find(user => user.id === userId);
  
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    const userData = {
      fullName: user.fullName,
      email: user.email,
      bio: user.bio,
      dob: user.dob
    };
  
    res.status(200).json({ message: 'Success', data: userData });
  });
const PORT = 3005;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
