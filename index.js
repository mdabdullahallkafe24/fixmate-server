
import express from "express";
import Stripe from "stripe";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import dns from "node:dns";

import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import {
  toNodeHandler,
  fromNodeHeaders,
} from "better-auth/node";
import {
  createAuthMiddleware,
  APIError,
} from "better-auth/api";

// ==========================================
// DNS CONFIGURATION
// ==========================================

dns.setServers(["1.1.1.1", "8.8.8.8"]);

// ==========================================
// EXPRESS CONFIGURATION
// ==========================================

const app = express();
const PORT = process.env.PORT || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL || "http://localhost:3000";

// ==========================================
// ENVIRONMENT VALIDATION
// ==========================================

const requiredEnv = [
  "MONGODB_URI",
  "BETTER_AUTH_SECRET",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "BETTER_AUTH_URL",
  "STRIPE_SECRET_KEY",
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    throw new Error(`${key} is missing from .env`);
  }
}

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ==========================================
// CORS CONFIGURATION
// ==========================================

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ==========================================
// MONGODB CONFIGURATION
// ==========================================

const client = new MongoClient(process.env.MONGODB_URI);

const db = client.db(process.env.DB_NAME || "fixmate");

// Exactly four application collections
const userCollection = db.collection("users");
const serviceCollection = db.collection("services");
const bookingCollection = db.collection("bookings");
const paymentCollection = db.collection("payments");

// ==========================================
// BETTER AUTH CONFIGURATION
// ==========================================

const auth = betterAuth({
  appName: "FixMate",
  baseURL: process.env.BETTER_AUTH_URL,
  secret: process.env.BETTER_AUTH_SECRET,
  trustedOrigins: [CLIENT_URL],

  database: mongodbAdapter(db, {
    client,
  }),
account: {
  accountLinking: {
    enabled: true,
    trustedProviders: ["google"],
  },
},

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
  },

  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
  },

  user: {
    modelName: "users",

    additionalFields: {
      role: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: false,
      },

      roleSelectionPending: {
        type: "boolean",
        required: false,
        defaultValue: true,
        input: false,
      },

      phone: {
        type: "string",
        required: false,
      },

      area: {
        type: "string",
        required: false,
      },

      bio: {
        type: "string",
        required: false,
      },
    },
  },

  // Server-side password validation
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path === "/sign-up/email") {
        const password = ctx.body?.password;

        if (
          typeof password !== "string" ||
          password.length < 6 ||
          !/[A-Z]/.test(password) ||
          !/[a-z]/.test(password)
        ) {
          throw new APIError("BAD_REQUEST", {
            message:
              "Password must contain at least 6 characters, one uppercase letter and one lowercase letter.",
          });
        }
      }
    }),
  },

  // Secure default role for every new account
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          return {
            data: {
              ...user,
              role: "customer",
              roleSelectionPending: true,
            },
          };
        },
      },
    },
  },
});

// ==========================================
// BETTER AUTH ROUTE
// Keep this before express.json()
// ==========================================

app.all("/api/auth/*splat", toNodeHandler(auth));

// ==========================================
// STRIPE: RECORD SUCCESSFUL PAYMENT
// =========================================


async function recordSuccessfulPayment(session) {
  if (session.payment_status !== "paid") {
    throw new Error("Stripe payment is not completed.");
  }

  const bookingId = session.metadata?.bookingId;
  const customerEmail = session.metadata?.customerEmail;

  if (
    !bookingId ||
    !ObjectId.isValid(bookingId) ||
    !customerEmail
  ) {
    throw new Error("Invalid Stripe session metadata.");
  }

  const booking = await bookingCollection.findOne({
    _id: new ObjectId(bookingId),
    customerEmail,
    stripeSessionId: session.id,
  });

  if (!booking) {
    throw new Error("Matching booking not found.");
  }

  const expectedAmount = Math.round(
    Number(booking.finalAmount) * 100
  );

  if (
    !Number.isFinite(expectedAmount) ||
    session.amount_total !== expectedAmount
  ) {
    throw new Error("Payment amount mismatch.");
  }

  const expectedCurrency = (
    process.env.STRIPE_CURRENCY || "bdt"
  ).toLowerCase();

  if (session.currency !== expectedCurrency) {
    throw new Error("Payment currency mismatch.");
  }

  // Prevent duplicate payment records
  const existingPayment = await paymentCollection.findOne({
    stripeSessionId: session.id,
  });

  if (existingPayment?.status === "succeeded") {
    await bookingCollection.updateOne(
      { _id: booking._id },
      {
        $set: {
          paymentStatus: "paid",
          paymentIntentId: session.payment_intent,
          paidAt: existingPayment.paidAt || new Date(),
          updatedAt: new Date(),
        },
      }
    );

    return existingPayment;
  }

  const now = new Date();

  await paymentCollection.updateOne(
    { stripeSessionId: session.id },
    {
      $set: {
        bookingId: booking._id,
        serviceTitle: booking.serviceTitle || "FixMate Repair Service",
        customerName: booking.customerName || "",
        customerEmail: booking.customerEmail,
        technicianName: booking.technicianName || "",
        technicianEmail: booking.technicianEmail,
        amount: session.amount_total / 100,
        currency: session.currency,
        paymentStatus: "paid",
        status: "succeeded",
        transactionId: session.payment_intent,
        paymentIntentId: session.payment_intent,
        paidAt: now,
        updatedAt: now,
      },
      $setOnInsert: {
        createdAt: now,
      },
    },
    { upsert: true }
  );

  await bookingCollection.updateOne(
    {
      _id: booking._id,
      stripeSessionId: session.id,
    },
    {
      $set: {
        paymentStatus: "paid",
        paymentIntentId: session.payment_intent,
        paidAt: now,
        updatedAt: now,
      },
    }
  );

  return { success: true };
}



// ==========================================
// STRIPE WEBHOOK
// POST /api/payments/webhook
// Must be before express.json()
// ==========================================

app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      return res.status(500).json({
        success: false,
        message: "Stripe webhook secret is not configured.",
      });
    }

    let event;

    try {
      const signature = req.headers["stripe-signature"];

      event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        webhookSecret
      );
    } catch (error) {
      console.error(
        "Stripe webhook signature verification failed:",
        error.message
      );

      return res.status(400).send(`Webhook Error: ${error.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        await recordSuccessfulPayment(event.data.object);
      }

      return res.status(200).json({ received: true });
    } catch (error) {
      console.error("Stripe webhook processing error:", error);

      return res.status(500).json({
        success: false,
        message: "Stripe webhook processing failed.",
      });
    }
  }
);

// ==========================================
// EXPRESS BODY PARSER
// ==========================================

app.use(express.json());

// ==========================================
// AUTHENTICATED USER HELPER
// ==========================================

async function getAuthenticatedUser(req) {
  const session = await auth.api.getSession({
    headers: fromNodeHeaders(req.headers),
  });

  if (!session?.user?.email) {
    return null;
  }

  const user = await userCollection.findOne({
    email: session.user.email,
  });

  return user;
}

// ==========================================
// SERVICE CONFIGURATION
// ==========================================

const allowedCategories = [
  "Smartphone",
  "Laptop & PC",
  "AC",
  "Refrigerator",
  "TV",
  "Washing Machine",
  "Electrical",
];

const allowedServiceModes = [
  "Home Visit",
  "Shop Drop-off",
];

// ==========================================
// SERVICE IMAGE VALIDATION
// ==========================================

function isValidImageUrl(value) {
  if (typeof value !== "string" || !value.trim()) {
    return false;
  }

  try {
    const imageUrl = new URL(value.trim());
    const hostname = imageUrl.hostname.toLowerCase();

    const isImgBB =
      hostname === "ibb.co" ||
      hostname.endsWith(".ibb.co") ||
      hostname === "imgbb.com" ||
      hostname.endsWith(".imgbb.com");

    return imageUrl.protocol === "https:" && isImgBB;
  } catch {
    return false;
  }
}

// ==========================================
// USER: UPDATE OWN PROFILE
// PATCH /api/users/profile
// Email and role are intentionally not editable here.
// ==========================================

app.patch("/api/users/profile", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({ success: false, message: "Please sign in to update your profile." });
    }

    const body = req.body || {};
    const updates = {};

    if (Object.prototype.hasOwnProperty.call(body, "name")) {
      if (typeof body.name !== "string" || !body.name.trim() || body.name.trim().length > 80) {
        return res.status(400).json({ success: false, message: "Name must be between 1 and 80 characters." });
      }
      updates.name = body.name.trim();
    }

    if (Object.prototype.hasOwnProperty.call(body, "phone")) {
      if (typeof body.phone !== "string" || body.phone.trim().length > 20 || (body.phone.trim() && body.phone.trim().length < 7)) {
        return res.status(400).json({ success: false, message: "Please provide a valid phone number." });
      }
      updates.phone = body.phone.trim();
    }

    if (Object.prototype.hasOwnProperty.call(body, "area")) {
      if (typeof body.area !== "string" || body.area.trim().length > 120) {
        return res.status(400).json({ success: false, message: "Area must be 120 characters or fewer." });
      }
      updates.area = body.area.trim();
    }

    if (Object.prototype.hasOwnProperty.call(body, "bio")) {
      if (typeof body.bio !== "string" || body.bio.trim().length > 500) {
        return res.status(400).json({ success: false, message: "Bio must be 500 characters or fewer." });
      }
      updates.bio = body.bio.trim();
    }

    if (Object.prototype.hasOwnProperty.call(body, "image")) {
      if (typeof body.image !== "string" || !isValidImageUrl(body.image)) {
        return res.status(400).json({ success: false, message: "Please provide a valid ImgBB profile image URL." });
      }
      updates.image = body.image.trim();
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ success: false, message: "No valid profile fields were provided." });
    }

    updates.updatedAt = new Date();
    await userCollection.updateOne({ _id: user._id }, { $set: updates });

    const updatedUser = await userCollection.findOne(
      { _id: user._id },
      { projection: { name: 1, email: 1, image: 1, role: 1, phone: 1, area: 1, bio: 1 } }
    );

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    return res.status(500).json({ success: false, message: "Failed to update profile." });
  }
});

// ==========================================
// COMPLETE SIGNUP ROLE SELECTION
// POST /api/complete-signup-role
// ==========================================

app.post("/api/complete-signup-role", async (req, res) => {
  try {
    if (req.headers.origin !== CLIENT_URL) {
      return res.status(403).json({
        success: false,
        message: "Invalid request origin.",
      });
    }

    const { role } = req.body || {};

    if (!["customer", "technician"].includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid account role.",
      });
    }

    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });

    if (!session?.user?.email) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    const result = await userCollection.updateOne(
      {
        email: session.user.email,
        roleSelectionPending: true,
      },
      {
        $set: {
          role,
          roleSelectionPending: false,
          updatedAt: new Date(),
        },
      }
    );

    if (result.modifiedCount !== 1) {
      return res.status(409).json({
        success: false,
        message:
          "Role selection is not available for this account.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Account role saved successfully.",
      role,
    });
  } catch (error) {
    console.error("Role completion error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to complete account role selection.",
    });
  }
});

// ==========================================
// PUBLIC: GET APPROVED AND AVAILABLE SERVICES
// GET /api/services
// ==========================================
// Place this helper before the API route
const escapeRegex = (value) => {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
};

// Get approved and available services with server-side filters
app.get("/api/services", async (req, res) => {
  try {
    const {
      q = "",
      category = "",
      serviceMode = "",
      maxPrice = "",
      sort = "newest",
    } = req.query;

    const searchText = String(q).trim();
    const selectedCategory = String(category).trim();
    const selectedServiceMode = String(serviceMode).trim();
    const priceValue = String(maxPrice).trim();
    const sortValue = String(sort).trim();

    // Always show only approved and available services
    const filter = {
      approvalStatus: "approved",
      isAvailable: true,
    };

    // Search by title, description, category, technician or area
    if (searchText) {
      const safeSearch = new RegExp(escapeRegex(searchText), "i");

      filter.$or = [
        { title: safeSearch },
        { description: safeSearch },
        { category: safeSearch },
        { technicianName: safeSearch },
        { serviceArea: safeSearch },
      ];
    }

    // Category filter
    if (selectedCategory && selectedCategory !== "All") {

      filter.category = selectedCategory;
    }

    // Service mode filter
    if (selectedServiceMode && selectedServiceMode !== "All") {
      filter.serviceMode = selectedServiceMode;
    }

    // Maximum price filter
    if (priceValue !== "") {
      const parsedPrice = Number(priceValue);

      if (!Number.isFinite(parsedPrice) || parsedPrice < 0) {
        return res.status(400).json({
          success: false,
          message: "Please provide a valid maximum price.",
        });
      }

      filter.basePrice = { $lte: parsedPrice };
    }

    // Sorting options
    let sortOptions = { createdAt: -1 };

    if (sortValue === "low-to-high") {
      sortOptions = { basePrice: 1, createdAt: -1 };
    } else if (sortValue === "high-to-low") {
      sortOptions = { basePrice: -1, createdAt: -1 };
    } else if (sortValue === "newest" || sortValue === "default") {
      sortOptions = { createdAt: -1 };
    } else {
      return res.status(400).json({
        success: false,
        message: "Invalid sorting option.",
      });
    }

    const services = await serviceCollection
      .find(filter)
      .sort(sortOptions)
      .toArray();

    // Get actual service modes from approved and available services
    const serviceModes = await serviceCollection.distinct("serviceMode", {
      approvalStatus: "approved",
      isAvailable: true,
      serviceMode: { $exists: true, $nin: ["", null] },
    });

    return res.status(200).json({
      success: true,
      message: "Available services fetched successfully.",
      totalServices: services.length,
      serviceModes,
      services,
    });
  } catch (error) {
    console.error("Public get services error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch available services.",
    });
  }
});


// ==========================================
// TECHNICIAN: ADD NEW SERVICE
// POST /api/services
// ==========================================

app.post("/api/services", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to add a service.",
      });
    }

    if (user.role !== "technician") {
      return res.status(403).json({
        success: false,
        message: "Only technicians can add services.",
      });
    }

    const {
      title,
      category,
      description,
      basePrice,
      estimatedDuration,
      serviceMode,
      serviceArea,
      image,
    } = req.body || {};

    if (
      typeof title !== "string" ||
      !title.trim() ||
      typeof category !== "string" ||
      typeof description !== "string" ||
      !description.trim() ||
      basePrice === undefined ||
      typeof estimatedDuration !== "string" ||
      !estimatedDuration.trim() ||
      typeof serviceMode !== "string" ||
      typeof serviceArea !== "string" ||
      !serviceArea.trim() ||
      typeof image !== "string" ||
      !image.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required service information.",
      });
    }

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service category.",
      });
    }

    if (!allowedServiceModes.includes(serviceMode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service mode.",
      });
    }

    const price = Number(basePrice);

    if (!Number.isFinite(price) || price <= 0) {
      return res.status(400).json({
        success: false,
        message: "Base price must be a positive number.",
      });
    }

    if (!isValidImageUrl(image)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid ImgBB image URL.",
      });
    }

    const newService = {
      title: title.trim(),
      category,
      description: description.trim(),
      image: image.trim(),
      basePrice: price,
      estimatedDuration: estimatedDuration.trim(),
      serviceMode,
      serviceArea: serviceArea.trim(),

      technicianName: user.name,
      technicianEmail: user.email,

      approvalStatus: "pending",
      isAvailable: true,

      createdAt: new Date(),
    };

    const result = await serviceCollection.insertOne(newService);

    return res.status(201).json({
      success: true,
      message:
        "Service added successfully. Waiting for admin approval.",
      insertedId: result.insertedId,
      service: {
        ...newService,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Add service error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to add service. Please try again.",
    });
  }
});




// ==========================================
// VERIFY STRIPE CHECKOUT PAYMENT
// ==========================================

app.post("/api/payments/verify-checkout-session", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to verify your payment.",
      });
    }

    if (user.role !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can verify payments.",
      });
    }

    const { sessionId } = req.body;

    if (!sessionId || typeof sessionId !== "string") {
      return res.status(400).json({
        success: false,
        message: "A valid Stripe session ID is required.",
      });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status !== "paid") {
      return res.status(409).json({
        success: false,
        message: "Payment has not been completed yet.",
        paymentStatus: session.payment_status,
      });
    }

    const bookingId = session.metadata?.bookingId;
    const customerEmail = session.metadata?.customerEmail;

    if (
      !bookingId ||
      !ObjectId.isValid(bookingId) ||
      !customerEmail ||
      customerEmail.toLowerCase() !== user.email.toLowerCase()
    ) {
      return res.status(403).json({
        success: false,
        message: "Payment session does not belong to this customer.",
      });
    }

    const booking = await bookingCollection.findOne({
      _id: new ObjectId(bookingId),
      customerEmail: user.email,
    });

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Associated booking was not found.",
      });
    }

    if (booking.stripeSessionId !== session.id) {
      return res.status(403).json({
        success: false,
        message: "Stripe session does not match this booking.",
      });
    }

    const expectedAmount = Math.round(
      Number(booking.finalAmount) * 100
    );

    if (
      !Number.isFinite(expectedAmount) ||
      session.amount_total !== expectedAmount
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment amount does not match the booking amount.",
      });
    }

    const expectedCurrency = (
      process.env.STRIPE_CURRENCY || "bdt"
    ).toLowerCase();

    if (session.currency !== expectedCurrency) {
      return res.status(400).json({
        success: false,
        message: "Payment currency does not match.",
      });
    }

    await recordSuccessfulPayment(session);

    return res.status(200).json({
      success: true,
      message: "Payment verified successfully.",
      paymentStatus: "paid",
      bookingId,
    });
  } catch (error) {
    console.error("Stripe payment verification error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to verify Stripe payment.",
    });
  }
});



// ==========================================
// TECHNICIAN: GET MY SERVICES
// GET /api/services/my-services
// ==========================================

app.get("/api/services/my-services", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "technician") {
      return res.status(403).json({
        success: false,
        message: "Only technicians can access their services.",
      });
    }

    const services = await serviceCollection
      .find({
        technicianEmail: user.email,
      })
      .sort({
        createdAt: -1,
      })
      .toArray();

    return res.status(200).json({
      success: true,
      services,
    });
  } catch (error) {
    console.error("Get my services error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch your services.",
    });
  }
});

// ==========================================
// PUBLIC: GET SINGLE APPROVED SERVICE
// GET /api/services/:id
// ==========================================

app.get("/api/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID.",
      });
    }

    const service = await serviceCollection.findOne({
      _id: new ObjectId(id),
      approvalStatus: "approved",
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found or currently unavailable.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Service details fetched successfully.",
      service,
    });
  } catch (error) {
    console.error("Get single service error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch service details.",
    });
  }
});

// ==========================================
// CUSTOMER: CREATE NEW BOOKING
// POST /api/bookings
// ==========================================

app.post("/api/bookings", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to book a service.",
      });
    }

    if (user.role !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can book a service.",
      });
    }

    const {
      serviceId,
      phone,
      address,
      preferredDate,
      problemDescription,
    } = req.body || {};

    if (
      typeof serviceId !== "string" ||
      !ObjectId.isValid(serviceId)
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid service ID.",
      });
    }

    if (
      typeof phone !== "string" ||
      !phone.trim() ||
      typeof address !== "string" ||
      !address.trim() ||
      typeof preferredDate !== "string" ||
      typeof problemDescription !== "string" ||
      problemDescription.trim().length < 20
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required booking information. Problem description must be at least 20 characters.",
      });
    }

    const cleanPhone = phone.trim();

    if (cleanPhone.length < 7 || cleanPhone.length > 20) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid phone number.",
      });
    }

    const datePattern = /^\d{4}-\d{2}-\d{2}$/;

    if (!datePattern.test(preferredDate)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid preferred date.",
      });
    }

    const parsedDate = new Date(
      `${preferredDate}T00:00:00.000Z`
    );

    if (
      Number.isNaN(parsedDate.getTime()) ||
      parsedDate.toISOString().slice(0, 10) !== preferredDate
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid calendar date.",
      });
    }

    const todayDate = new Date().toISOString().slice(0, 10);

    if (preferredDate <= todayDate) {
      return res.status(400).json({
        success: false,
        message: "Preferred date must be a future date.",
      });
    }

    const service = await serviceCollection.findOne({
      _id: new ObjectId(serviceId),
      approvalStatus: "approved",
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "This service is not available for booking.",
      });
    }

    if (
      String(service.technicianEmail || "").toLowerCase() ===
      String(user.email || "").toLowerCase()
    ) {
      return res.status(403).json({
        success: false,
        message: "You cannot book your own repair service.",
      });
    }

    const existingActiveBooking = await bookingCollection.findOne({
      serviceId: service._id,
      customerEmail: user.email,
      status: {
        $in: [
          "requested",
          "accepted",
          "in-progress",
          "awaiting-payment",
        ],
      },
    });

    if (existingActiveBooking) {
      return res.status(409).json({
        success: false,
        message: "You already have an active booking for this service.",
        bookingId: existingActiveBooking._id,
      });
    }

    const activeBookingKey = `${service._id.toString()}_${user.email.toLowerCase()}`;

    const newBooking = {
      serviceId: service._id,
      serviceTitle: service.title,
      serviceImage: service.image,
      category: service.category,
      basePrice: service.basePrice,

      technicianName: service.technicianName,
      technicianEmail: service.technicianEmail,

      customerName: user.name,
      customerEmail: user.email,
      customerPhone: cleanPhone,
      address: address.trim(),
      preferredDate,
      problemDescription: problemDescription.trim(),

      status: "requested",
      paymentStatus: "unpaid",

      activeBookingKey,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    try {
      const result = await bookingCollection.insertOne(newBooking);

      return res.status(201).json({
        success: true,
        message: "Booking request submitted successfully.",
        bookingId: result.insertedId,
        booking: {
          ...newBooking,
          _id: result.insertedId,
        },
      });
    } catch (insertError) {
      if (insertError.code === 11000) {
        return res.status(409).json({
          success: false,
          message: "You already have an active booking for this service.",
        });
      }

      throw insertError;
    }
  } catch (error) {
    console.error("Create booking error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to create booking.",
    });
  }
});

// ==========================================
// CUSTOMER: GET MY BOOKINGS
// GET /api/bookings/my-bookings
// ==========================================

app.get(["/api/bookings/my", "/api/bookings/my-bookings"], async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to view your bookings.",
      });
    }

    if (user.role !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can access their bookings.",
      });
    }

    const bookings = await bookingCollection
      .find({ customerEmail: user.email })
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Your bookings fetched successfully.",
      bookings,
    });
  } catch (error) {
    console.error("Get my bookings error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch your bookings.",
    });
  }
});

// ==========================================
// CUSTOMER: CANCEL A REQUESTED BOOKING
// PATCH /api/bookings/:id/cancel
// ==========================================

app.patch("/api/bookings/:id/cancel", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can cancel bookings.",
      });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid booking ID.",
      });
    }

    const now = new Date();

    const result = await bookingCollection.updateOne(
      {
        _id: new ObjectId(id),
        customerEmail: user.email,
        status: "requested",
        paymentStatus: { $ne: "paid" },
      },
      {
        $set: {
          status: "cancelled",
          cancelledAt: now,
          updatedAt: now,
        },
        $unset: {
          activeBookingKey: "",
        },
      }
    );

    if (result.matchedCount === 0) {
      const booking = await bookingCollection.findOne({
        _id: new ObjectId(id),
        customerEmail: user.email,
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found.",
        });
      }

      return res.status(409).json({
        success: false,
        message: "Only a requested, unpaid booking can be cancelled.",
        currentStatus: booking.status,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Booking cancelled successfully.",
      status: "cancelled",
    });
  } catch (error) {
    console.error("Cancel booking error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to cancel booking.",
    });
  }
});

// ==========================================
// TECHNICIAN: GET MY REPAIR REQUESTS
// GET /api/bookings/technician-requests
// ==========================================

app.get(
  ["/api/bookings/technician", "/api/bookings/technician-requests"],
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please sign in first.",
        });
      }

      if (user.role !== "technician") {
        return res.status(403).json({
          success: false,
          message: "Only technicians can view repair requests.",
        });
      }

      const bookings = await bookingCollection
        .find({ technicianEmail: user.email })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        message: "Repair requests fetched successfully.",
        bookings,
      });
    } catch (error) {
      console.error("Get technician requests error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to fetch repair requests.",
      });
    }
  }
);

// ==========================================
// TECHNICIAN: UPDATE BOOKING STATUS
// PATCH /api/bookings/:id/status
// ==========================================

app.patch("/api/bookings/:id/status", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "technician") {
      return res.status(403).json({
        success: false,
        message: "Only technicians can update booking status.",
      });
    }

    const { id } = req.params;
    const { status, finalAmount } = req.body || {};

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid booking ID.",
      });
    }

    const validStatuses = [
      "accepted",
      "rejected",
      "in-progress",
      "awaiting-payment",
      "completed",
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid booking status.",
      });
    }

    const bookingId = new ObjectId(id);

    const booking = await bookingCollection.findOne({
      _id: bookingId,
      technicianEmail: user.email,
    });

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: "Booking not found or you do not have permission.",
      });
    }

    const allowedTransitions = {
      requested: ["accepted", "rejected"],
      accepted: ["in-progress"],
      "in-progress": ["awaiting-payment"],
      "awaiting-payment": ["completed"],
    };

    const allowedNextStatuses =
      allowedTransitions[booking.status] || [];

    if (!allowedNextStatuses.includes(status)) {
      return res.status(409).json({
        success: false,
        message: `Cannot change booking status from ${booking.status} to ${status}.`,
        currentStatus: booking.status,
      });
    }

    const now = new Date();

    const updateFields = {
      status,
      updatedAt: now,
    };

    if (status === "awaiting-payment") {
      const amount = Number(finalAmount);

      if (
        finalAmount === undefined ||
        finalAmount === null ||
        finalAmount === "" ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "Please provide a valid final amount.",
        });
      }

      updateFields.finalAmount = amount;
      updateFields.paymentStatus = "unpaid";
      updateFields.amountRequestedAt = now;
      updateFields.stripeSessionId = null;
    }

    if (status === "completed") {
      if (booking.paymentStatus !== "paid") {
        return res.status(400).json({
          success: false,
          message:
            "Customer must complete payment before you confirm this repair.",
        });
      }

      updateFields.completedAt = now;
    }

    const updateOperation = { $set: updateFields };

    if (status === "rejected" || status === "completed") {
      updateOperation.$unset = {
        activeBookingKey: "",
      };
    }

    const result = await bookingCollection.updateOne(
      {
        _id: bookingId,
        technicianEmail: user.email,
        status: booking.status,
      },
      updateOperation
    );

    if (result.matchedCount === 0) {
      return res.status(409).json({
        success: false,
        message:
          "This request has already been processed. Please refresh.",
      });
    }

    return res.status(200).json({
      success: true,
      message:
        status === "awaiting-payment"
          ? "Final amount sent to customer successfully."
          : status === "completed"
            ? "Repair completion confirmed successfully."
            : `Booking status updated to ${status} successfully.`,
      status,
      finalAmount:
        status === "awaiting-payment"
          ? Number(finalAmount)
          : booking.finalAmount ?? null,
      completedAt: status === "completed" ? now : null,
      paymentStatus:
        status === "awaiting-payment"
          ? "unpaid"
          : booking.paymentStatus,
    });
  } catch (error) {
    console.error("Update booking status error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update booking status.",
    });
  }
});

// ==========================================
// TECHNICIAN: UPDATE SERVICE
// PATCH /api/services/:id
// PUT remains a backward-compatible alias
// ==========================================

const updateServiceHandler = async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please login first.",
      });
    }

    if (user.role !== "technician") {
      return res.status(403).json({
        success: false,
        message: "Only technicians can update services.",
      });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID.",
      });
    }

    const {
      title,
      category,
      description,
      image,
      basePrice,
      estimatedDuration,
      serviceMode,
      serviceArea,
    } = req.body || {};

    if (
      typeof title !== "string" ||
      !title.trim() ||
      typeof category !== "string" ||
      typeof description !== "string" ||
      !description.trim() ||
      typeof image !== "string" ||
      !image.trim() ||
      typeof estimatedDuration !== "string" ||
      !estimatedDuration.trim() ||
      typeof serviceMode !== "string" ||
      typeof serviceArea !== "string" ||
      !serviceArea.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required service information.",
      });
    }

    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service category.",
      });
    }

    if (!allowedServiceModes.includes(serviceMode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service mode.",
      });
    }

    const price = Number(basePrice);

    if (!Number.isFinite(price) || price <= 0) {
      return res.status(400).json({
        success: false,
        message: "Base price must be a positive number.",
      });
    }

    if (!isValidImageUrl(image)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid ImgBB image URL.",
      });
    }

    const updatedService = {
      title: title.trim(),
      category,
      description: description.trim(),
      image: image.trim(),
      basePrice: price,
      estimatedDuration: estimatedDuration.trim(),
      serviceMode,
      serviceArea: serviceArea.trim(),
      approvalStatus: "pending",
      updatedAt: new Date(),
    };

    const result = await serviceCollection.updateOne(
      {
        _id: new ObjectId(id),
        technicianEmail: user.email,
      },
      {
        $set: updatedService,
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found or you do not own this service.",
      });
    }

    return res.status(200).json({
      success: true,
      message:
        "Service updated successfully. Waiting for admin approval.",
    });
  } catch (error) {
    console.error("Update service error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update service.",
    });
  }
};

app.patch("/api/services/:id", updateServiceHandler);
app.put("/api/services/:id", updateServiceHandler);

// ==========================================
// TECHNICIAN: TOGGLE SERVICE AVAILABILITY
// PATCH /api/services/:id/availability
// ==========================================

app.patch(
  "/api/services/:id/availability",
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please login first.",
        });
      }

      if (user.role !== "technician") {
        return res.status(403).json({
          success: false,
          message: "Only technicians can change availability.",
        });
      }

      const { id } = req.params;
      const { isAvailable } = req.body || {};

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      if (typeof isAvailable !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "isAvailable must be true or false.",
        });
      }

      const result = await serviceCollection.updateOne(
        {
          _id: new ObjectId(id),
          technicianEmail: user.email,
        },
        {
          $set: {
            isAvailable,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Service not found or you do not own this service.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Service is now ${
          isAvailable ? "available" : "unavailable"
        }.`,
        isAvailable,
      });
    } catch (error) {
      console.error("Availability update error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update availability.",
      });
    }
  }
);

// ==========================================
// TECHNICIAN: DELETE SERVICE
// DELETE /api/services/:id
// ==========================================

app.delete("/api/services/:id", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please login first.",
      });
    }

    if (user.role !== "technician") {
      return res.status(403).json({
        success: false,
        message: "Only technicians can delete services.",
      });
    }

    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID.",
      });
    }

    const result = await serviceCollection.deleteOne({
      _id: new ObjectId(id),
      technicianEmail: user.email,
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Service not found or you do not own this service.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Service deleted successfully.",
    });
  } catch (error) {
    console.error("Delete service error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to delete service.",
    });
  }
});

// ==========================================
// ADMIN: GET ALL SERVICES
// GET /api/admin/services
// ==========================================

app.get("/api/admin/services", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    const services = await serviceCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Services fetched successfully.",
      services,
    });
  } catch (error) {
    console.error("Admin get services error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch services.",
    });
  }
});

// ==========================================
// ADMIN: APPROVE OR REJECT SERVICE
// PATCH /api/admin/services/:id/approval
// ==========================================

app.patch(
  "/api/admin/services/:id/approval",
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please sign in first.",
        });
      }

      if (user.role !== "admin") {
        return res.status(403).json({
          success: false,
          message: "Admin access required.",
        });
      }

      const { id } = req.params;
      const { approvalStatus } = req.body || {};

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid service ID.",
        });
      }

      if (!["approved", "rejected"].includes(approvalStatus)) {
        return res.status(400).json({
          success: false,
          message: "Status must be approved or rejected.",
        });
      }

      const result = await serviceCollection.updateOne(
        {
          _id: new ObjectId(id),
        },
        {
          $set: {
            approvalStatus,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Service not found.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Service ${approvalStatus} successfully.`,
        approvalStatus,
      });
    } catch (error) {
      console.error("Admin approval error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to update service approval.",
      });
    }
  }
);

// ==========================================
// ADMIN: GET ALL BOOKINGS
// GET /api/admin/bookings
// ==========================================

app.get("/api/admin/bookings", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    const bookings = await bookingCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Bookings fetched successfully.",
      bookings,
    });
  } catch (error) {
    console.error("Admin get bookings error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch bookings.",
    });
  }
});

// ==========================================
// ADMIN: GET ALL USERS
// GET /api/admin/users
// ==========================================

app.get("/api/admin/users", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    const users = await userCollection
      .find(
        {},
        {
          projection: {
            name: 1,
            email: 1,
            image: 1,
            role: 1,
            phone: 1,
            area: 1,
            createdAt: 1,
          },
        }
      )
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Users fetched successfully.",
      users,
    });
  } catch (error) {
    console.error("Admin get users error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to fetch users.",
    });
  }
});

// ==========================================
// ADMIN: UPDATE USER ROLE
// PATCH /api/admin/users/:id/role
// ==========================================

app.patch("/api/admin/users/:id/role", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required.",
      });
    }

    const { id } = req.params;
    const { role } = req.body || {};

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user ID.",
      });
    }

    if (!["customer", "technician", "admin"].includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid user role.",
      });
    }

    const targetUserId = new ObjectId(id);

    if (user._id.toString() === targetUserId.toString()) {
      return res.status(403).json({
        success: false,
        message: "You cannot change your own role.",
      });
    }

    const result = await userCollection.updateOne(
      { _id: targetUserId },
      {
        $set: {
          role,
          roleSelectionPending: false,
          updatedAt: new Date(),
        },
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "User role updated successfully.",
      role,
    });
  } catch (error) {
    console.error("Admin update user role error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to update user role.",
    });
  }
});

// ==========================================
// CUSTOMER: CREATE STRIPE CHECKOUT SESSION
// POST /api/payments/create-checkout-session
// ==========================================

app.post(
  "/api/payments/create-checkout-session",
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please sign in first.",
        });
      }

      if (user.role !== "customer") {
        return res.status(403).json({
          success: false,
          message: "Only customers can make payments.",
        });
      }

      const { bookingId } = req.body || {};

      if (!ObjectId.isValid(bookingId || "")) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking ID.",
        });
      }

      const booking = await bookingCollection.findOne({
        _id: new ObjectId(bookingId),
        customerEmail: user.email,
      });

      if (!booking) {
        return res.status(404).json({
          success: false,
          message: "Booking not found.",
        });
      }

      if (booking.status !== "awaiting-payment") {
        return res.status(400).json({
          success: false,
          message:
            "Payment is available only after the technician requests the final amount.",
        });
      }

      if (booking.paymentStatus === "paid") {
        return res.status(400).json({
          success: false,
          message: "This booking has already been paid.",
        });
      }

      const amount = Number(booking.finalAmount);

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Invalid booking payment amount.",
        });
      }

      // Reuse an existing open Stripe Checkout session
      if (booking.stripeSessionId) {
        try {
          const existingSession =
            await stripe.checkout.sessions.retrieve(
              booking.stripeSessionId
            );

          if (
            existingSession.status === "open" &&
            existingSession.url
          ) {
            return res.status(200).json({
              success: true,
              checkoutUrl: existingSession.url,
              sessionId: existingSession.id,
            });
          }
        } catch (error) {
          console.error(
            "Existing Stripe session lookup:",
            error.message
          );
        }
      }

      const currency = (
        process.env.STRIPE_CURRENCY || "bdt"
      ).toLowerCase();

      const session = await stripe.checkout.sessions.create({
        mode: "payment",

        customer_email: user.email,

        line_items: [
          {
            price_data: {
              currency,
              product_data: {
                name:
                  booking.serviceTitle ||
                  "FixMate Repair Service",
                description: `Booking ID: ${booking._id.toString()}`,
              },
              unit_amount: Math.round(amount * 100),
            },
            quantity: 1,
          },
        ],

        metadata: {
          bookingId: booking._id.toString(),
          customerEmail: user.email,
        },

        success_url:
          `${CLIENT_URL}/dashboard/customer/bookings?payment=success&session_id={CHECKOUT_SESSION_ID}`,

        cancel_url:
          `${CLIENT_URL}/dashboard/customer/bookings?payment=cancelled`,
      });

      const updateResult = await bookingCollection.updateOne(
        {
          _id: booking._id,
          customerEmail: user.email,
          status: "awaiting-payment",
          paymentStatus: { $ne: "paid" },
        },
        {
          $set: {
            stripeSessionId: session.id,
            paymentStatus: "pending",
            updatedAt: new Date(),
          },
        }
      );

      if (updateResult.matchedCount === 0) {
        return res.status(409).json({
          success: false,
          message:
            "Booking payment status changed. Please refresh and try again.",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Stripe checkout session created successfully.",
        checkoutUrl: session.url,
        sessionId: session.id,
      });
    } catch (error) {
      console.error(
        "Create Stripe checkout session error:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Failed to create payment session.",
      });
    }
  }
);

// ==========================================
// CUSTOMER: GET MY PAYMENT HISTORY
// GET /api/payments/my-payments
// ==========================================

app.get("/api/payments/my-payments", async (req, res) => {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to view your payments.",
      });
    }

    if (user.role !== "customer") {
      return res.status(403).json({
        success: false,
        message: "Only customers can view payment history.",
      });
    }

    const payments = await paymentCollection
      .find({
        customerEmail: user.email,
      })
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Payment history fetched successfully.",
      payments,
    });
  } catch (error) {
    console.error(
      "Get customer payment history error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Failed to fetch payment history.",
    });
  }
});

// ==========================================
// ADMIN: GET ALL PAYMENT TRANSACTIONS
// GET /api/admin/transactions
// ==========================================

app.get(
  ["/api/admin/payments", "/api/admin/transactions"],
  async (req, res) => {
    try {
      const user = await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Please sign in first.",
        });
      }

      if (user.role !== "admin") {
        return res.status(403).json({
          success: false,
          message: "Only admins can view transactions.",
        });
      }

      const transactions = await paymentCollection
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

      const revenueResult = await paymentCollection
        .aggregate([
          {
            $match: {
              status: "succeeded",
            },
          },
          {
            $group: {
              _id: null,
              totalRevenue: {
                $sum: "$amount",
              },
              totalTransactions: {
                $sum: 1,
              },
            },
          },
        ])
        .toArray();

      const totalRevenue =
        revenueResult[0]?.totalRevenue || 0;

      const totalTransactions =
        revenueResult[0]?.totalTransactions || 0;

      return res.status(200).json({
        success: true,
        message: "Transactions fetched successfully.",
        transactions,
        payments: transactions,
        summary: {
          totalRevenue,
          totalTransactions,
        },
      });
    } catch (error) {
      console.error("Admin transactions error:", error);

      return res.status(500).json({
        success: false,
        message: "Failed to fetch transactions.",
      });
    }
  }
);

// ==========================================
// ROOT API
// ==========================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "FixMate Server is Running!",
  });
});

// ==========================================
// HEALTH CHECK API
// ==========================================

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "FixMate API is healthy!",
    database: db.databaseName,
    collections: [
      "users",
      "services",
      "bookings",
      "payments",
    ],
  });
});

// ==========================================
// START SERVER
// ==========================================

async function run() {
  try {
    await client.connect();

    await paymentCollection.createIndex(
      {
        stripeSessionId: 1,
      },
      {
        unique: true,
        sparse: true,
      }
    );

    await bookingCollection.createIndex({
      customerEmail: 1,
      createdAt: -1,
    });

    await bookingCollection.createIndex({
      technicianEmail: 1,
      createdAt: -1,
    });

    await bookingCollection.createIndex(
      { activeBookingKey: 1 },
      { unique: true, sparse: true }
    );

    await bookingCollection.createIndex({
      serviceId: 1,
      customerEmail: 1,
      status: 1,
    });

    await serviceCollection.createIndex({
      approvalStatus: 1,
      isAvailable: 1,
      createdAt: -1,
    });

    await paymentCollection.createIndex({
      customerEmail: 1,
      createdAt: -1,
    });

    console.log("MongoDB Atlas connected successfully!");
    console.log("Database connected:", db.databaseName);

    app.listen(PORT, () => {
      console.log(`FixMate server is running on port ${PORT}`);
      console.log("Better Auth is configured!");
      console.log("Google Authentication is configured!");
      console.log("Secure role selection API is configured!");

      console.log("Public Get Approved Services API is configured!");
      console.log("Public Get Single Service API is configured!");

      console.log("Technician Add Service API is configured!");
      console.log("Technician My Services API is configured!");
      console.log("Technician Update Service API is configured!");
      console.log("Technician Availability API is configured!");
      console.log("Technician Delete Service API is configured!");

      console.log("Customer Create Booking API is configured!");
      console.log("Customer My Bookings API is configured!");
      console.log("Customer Cancel Booking API is configured!");
      console.log("User Profile Update API is configured!");

      console.log("Technician Repair Requests API is configured!");
      console.log("Technician Booking Status Workflow is configured!");

      console.log("Admin Get All Services API is configured!");
      console.log("Admin Get All Bookings API is configured!");
      console.log("Admin Get All Users API is configured!");
      console.log("Admin Approve/Reject Service API is configured!");
      console.log("Admin Update User Role API is configured!");

      console.log("Stripe Checkout and Webhook APIs are configured!");
      console.log("Customer Payment History API is configured!");
      console.log("Admin Transactions API is configured!");
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

run();

export default app;
