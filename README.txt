# Dama Mart — Customer Tracking + My Orders + Admin Order Status

## Front-end demo
Open `index.html` in a browser.

Demo customer:
- Username: test@damamart.com
- Password: DamaTest@2026

Demo admin:
- Username: admin@damamart.com
- Password: DamaAdmin@2026

## Features
- Customer My Orders
- Order ID generation
- Track Order
- 5-stage order status
- Admin order list
- Admin status updates
- Delivery boy assignment
- WhatsApp order message
- LocalStorage demo persistence

## Production backend
1. Install Node.js.
2. Run `npm install`
3. Copy `.env.example` to `.env` and set a strong ADMIN_PASS.
4. Run `npm start`.
5. For production, replace the in-memory `orders` array with MongoDB/PostgreSQL and connect the front-end API calls to the deployed server.
