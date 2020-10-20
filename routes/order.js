const express = require("express");
const router = express.Router();

const { requireSignin, adminMiddleware } = require("../controllers/auth");
const { userById, addOrderToUserHistory } = require("../controllers/user");
const {
    create,
    listOrders,
    getStatusValues,
    orderById,
    updateOrderStatus
} = require("../controllers/order");
const { decreaseQuantity } = require("../controllers/product");

router.post(
    "/order/create/:userId",
    requireSignin,
    addOrderToUserHistory,
    decreaseQuantity,
    create
);

router.get("/order/list/:userId", requireSignin, adminMiddleware, listOrders);
router.get(
    "/order/status-values/:userId",
    requireSignin,
adminMiddleware,
    getStatusValues
);
router.put(
    "/order/:orderId/status/:userId",
    requireSignin,
    adminMiddleware,
    updateOrderStatus
);

router.param("userId", userById);
router.param("orderId", orderById);

module.exports = router;
