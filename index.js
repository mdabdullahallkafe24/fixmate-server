
import express from "express";
import cors from "cors";
import { MongoClient } from "mongodb";
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

// DNS configuration
dns.setServers(["1.1.1.1", "8.8.8.8"]);

const app = express();
const PORT = process.env.PORT || 5000;

const CLIENT_URL =
  process.env.CLIENT_URL || "http://localhost:3000";

// Environment validation
const requiredEnv = [
  "MONGODB_URI",
  "BETTER_AUTH_SECRET",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "BETTER_AUTH_URL",
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    throw new Error(`${key} is missing from .env`);
  }
}

// CORS configuration
app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// MongoDB configuration
const client = new MongoClient(process.env.MONGODB_URI);
const db = client.db(process.env.DB_NAME || "fixmate");

// Application collections
const userCollection = db.collection("users");
const serviceCollection = db.collection("services");
const bookingCollection = db.collection("bookings");
const paymentCollection = db.collection("payments");

// Better Auth configuration
const auth = betterAuth({
  appName: "FixMate",

  baseURL: process.env.BETTER_AUTH_URL,

  secret: process.env.BETTER_AUTH_SECRET,

  trustedOrigins: [CLIENT_URL],

  database: mongodbAdapter(db, {
    client,
  }),

  // Email and Password Authentication
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 6,
  },

  // Google Authentication
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
  },

  // User collection and additional fields
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

  // Secure default role for every newly created account
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

// Better Auth route
// Keep this before express.json()
app.all("/api/auth/*splat", toNodeHandler(auth));

// Express body parser
app.use(express.json());

// Get authenticated user
async function getAuthenticatedUser(req) {
  const session = await auth.api.getSession({
    headers: fromNodeHeaders(req.headers),
  });

  if (!session?.user?.email) {
    return null;
  }

  // Read the latest user data from MongoDB
  const user = await userCollection.findOne({
    email: session.user.email,
  });

  return user;
}

// Complete signup role selection
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
// TECHNICIAN: ADD NEW SERVICE
// POST /api/services
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

app.post("/api/services", async (req, res) => {
  try {
    // Verify login
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please sign in to add a service.",
      });
    }

    // Only technicians can add services
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

    // Required field validation
    if (
      !title?.trim() ||
      !category ||
      !description?.trim() ||
      basePrice === undefined ||
      !estimatedDuration?.trim() ||
      !serviceMode ||
      !serviceArea?.trim() ||
      !image?.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required service information.",
      });
    }

    // Category validation
    if (!allowedCategories.includes(category)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service category.",
      });
    }

    // Service mode validation
    if (!allowedServiceModes.includes(serviceMode)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service mode.",
      });
    }

    // Price validation
    const price = Number(basePrice);

    if (!Number.isFinite(price) || price <= 0) {
      return res.status(400).json({
        success: false,
        message: "Base price must be a positive number.",
      });
    }

    // Validate ImgBB image URL
    let imageUrl;

    try {
      imageUrl = new URL(image.trim());

      const hostname = imageUrl.hostname.toLowerCase();

      const isImgBB =
        hostname === "ibb.co" ||
        hostname.endsWith(".ibb.co") ||
        hostname === "imgbb.com" ||
        hostname.endsWith(".imgbb.com");

      if (imageUrl.protocol !== "https:" || !isImgBB) {
        return res.status(400).json({
          success: false,
          message: "Please provide a valid ImgBB image URL.",
        });
      }
    } catch {
      return res.status(400).json({
        success: false,
        message: "Invalid service image URL.",
      });
    }

    // Create service document
    const newService = {
      title: title.trim(),
      category,
      description: description.trim(),
      image: imageUrl.href,
      basePrice: price,
      estimatedDuration: estimatedDuration.trim(),
      serviceMode,
      serviceArea: serviceArea.trim(),

      // Taken from the authenticated database user
      technicianName: user.name,
      technicianEmail: user.email,

      // New services must wait for admin approval
      approvalStatus: "pending",
      isAvailable: true,

      createdAt: new Date(),
    };

    const result = await serviceCollection.insertOne(newService);

    return res.status(201).json({
      success: true,
      message: "Service added successfully. Waiting for admin approval.",
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

// Root API
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "FixMate Server is Running!",
  });
});

// Health check API
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

// Start server
async function run() {
  try {
    await client.connect();

    console.log("MongoDB Atlas connected successfully!");
    console.log("Database connected:", db.databaseName);

    app.listen(PORT, () => {
      console.log(`FixMate server is running on port ${PORT}`);
      console.log("Better Auth is configured!");
      console.log("Google Authentication is configured!");
      console.log("Secure role selection API is configured!");
      console.log("Technician Add Service API is configured!");
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

run();

export default app;



