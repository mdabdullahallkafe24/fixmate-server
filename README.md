# FixMate – Backend API

FixMate is a smart home appliance and device repair booking platform. This repository contains the backend server that handles authentication, user management, repair services, booking management, role-based authorization, and secure Stripe payments.

## 🌐 Live Website

**Frontend URL:** [Add your deployed frontend URL]

## 🔗 Frontend Repository

[Add your frontend GitHub repository URL]

## 🚀 Key Features

### Authentication & Authorization
- Secure authentication with BetterAuth integration.
- JWT-based API authorization.
- Role-based access control for Customer, Technician, and Admin.
- Protected API endpoints.
- User profile management.

### Service Management
- Create, update, and delete repair services.
- Upload service images using ImgBB.
- Admin service approval and rejection.
- Control service availability.
- Public access to approved and available services.
- Server-side service search, filtering, and sorting.

### Booking Management
- Customers can request repair services.
- Prevent duplicate active booking requests.
- Technicians can accept or reject requests.
- Update repair progress.
- Set final repair amounts.
- Customers can cancel eligible pending requests.
- Role-based booking access and ownership validation.

### Payment Management
- Stripe Checkout integration.
- Secure payment session creation.
- Server-side payment amount validation.
- Stripe webhook integration.
- Duplicate payment prevention.
- Payment history and transaction management.

### Admin Management
- Manage users and user roles.
- Approve or reject services.
- Monitor all bookings.
- View payment transactions.
- Track platform revenue.

## 🛠️ Technologies Used

- Node.js
- Express.js
- MongoDB
- BetterAuth
- JSON Web Token (JWT)
- Stripe
- ImgBB API
- dotenv
- CORS

## 📦 Installation & Setup

### 1. Clone the repository

```bash
git clone YOUR_BACKEND_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd fixmate-server
```

### 3. Install dependencies

```bash
npm install
```

### 4. Configure environment variables

Create a `.env` file in the project root and configure the required variables.

```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
BETTER_AUTH_SECRET=your_better_auth_secret
BETTER_AUTH_URL=http://localhost:3000
JWT_SECRET=your_jwt_secret
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret
IMGBB_API_KEY=your_imgbb_api_key
CLIENT_URL=http://localhost:3000
```

**Important:** Use your actual environment variable names from the server code. Never commit `.env` files or expose secret keys on GitHub.

### 5. Start the development server

```bash
npm run dev
```

The backend server will run at:

[http://localhost:5000](http://localhost:5000)

## 🔌 API Overview

The backend provides RESTful API endpoints for the following modules:

| Module | Main Operations |
|---|---|
| Authentication | User authentication and authorization |
| Users | Profile updates and user management |
| Services | Create, read, update, delete, search, and approval |
| Bookings | Create requests, manage statuses, and cancel bookings |
| Payments | Stripe Checkout and payment history |
| Admin | User, service, booking, and transaction management |

## 👥 User Roles

| Role | Access |
|---|---|
| Customer | Browse services, create bookings, cancel eligible bookings, and make payments |
| Technician | Manage services and repair requests |
| Admin | Manage users, approve services, and monitor bookings and payments |

## 💳 Stripe Payment Testing

FixMate uses Stripe Checkout in test mode.

Use the following test card:

- **Card Number:** 4242 4242 4242 4242
- **Expiry Date:** Any future date
- **CVC:** Any 3 digits
- **ZIP:** Any valid ZIP code

## 🔐 Security

- Environment variables protect sensitive credentials.
- JWT middleware protects private API routes.
- Role-based middleware restricts unauthorized access.
- Ownership validation protects customer and technician data.
- Server-side validation enforces booking and payment rules.
- Stripe webhook handling helps prevent duplicate payment records.

## 📄 License

This project was developed as part of an academic assignment.
