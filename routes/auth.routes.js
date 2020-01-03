const { Router } = require('express');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const config = require('config')

const router = Router();

//app/auth/register
router.post('/register',
  [
    check('email', 'wrong email').isEmail(),
    check('pasword', 'minimal password length is 6 symbols').isLength({ min: 6 })
  ],
  async (req, res) => {
    console.log(req.body)
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'incorrect data on registration'
        })
      }

      const { email, password } = req.body;
      const candidate = await User.findOne({ email });

      if (candidate) return res.status(400).json({message: 'this user already exist'});

      const hashedPassword = await bcrypt(password, 12);
      const user = new User({ email, password: hashedPassword });

      await user.save();
      res.status(201).json({message:'User created'});

    } catch (e) {
      res.status(500).json({message:'something was wrong, try again'})
    }
  })

//app/auth/login
router.post('/login',
  [
    check('email', 'enter correct email').normalizeEmail().isEmail(),
    check('password', 'enter password').exists()
  ],
  async (res, req) => {
    try {
      const errors = validationResult(req)

      if (!errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'incorrect data with login'
        })
      }

      const { email, password } = req.body;

      const user = await User.findOne({ email });

      if (!user) {
        return res.status(400).json({message: 'User not found'});
      }
      
      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({message: 'wrong password, try again'})
      }

      const token = jwt.sign(
        { userId: user.id }, 
        config.get('jwtSecred'),
        { expiresIn: '1h' }
      )

      res.json({token, userId: user.id})

    } catch (e) {
      res.status(500).json({message: 'something was wrong, try again'})
    }

  })


module.exports = router;