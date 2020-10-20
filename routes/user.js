const express = require('express');
const router = express.Router();

const { requireSignin,adminMiddleware} = require('../controllers/auth');

const { userById, read, update, purchaseHistory } = require('../controllers/user');

router.get('/secret', requireSignin, (req, res) => {
    res.json({
        user: 'got here yay'
    });
});

router.get("/user/:id",requireSignin ,read )
router.put("/user/update",requireSignin ,update )
router.put("/user/admin/update",adminMiddleware,update )
router.get('/orders/by/user/:userId', requireSignin, purchaseHistory);

router.param('userId', userById);

module.exports = router;
