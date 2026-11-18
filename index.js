
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
      // Role is controlled by the backend only
      role: {
        type: "string",
        required: false,
        defaultValue: "customer",
        input: false,
      },

      // Only newly created accounts can complete role selection
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

              // Public signup can NEVER create an admin
              role: "customer",

              // Allow one-time customer/technician selection
              roleSelectionPending: true,
            },
          };
        },
      },
    },
  },
});

// Better Auth route
// IMPORTANT: Keep this before express.json()
app.all("/api/auth/*splat", toNodeHandler(auth));

// Express body parser
app.use(express.json());

// Complete signup role selection
app.post("/api/complete-signup-role", async (req, res) => {
  try {
    // Check frontend origin
    if (req.headers.origin !== CLIENT_URL) {
      return res.status(403).json({
        success: false,
        message: "Invalid request origin.",
      });
    }

    const { role } = req.body || {};

    // Only customer and technician are allowed
    if (!["customer", "technician"].includes(role)) {
      return res.status(400).json({
        success: false,
        message: "Invalid account role.",
      });
    }

    // Verify authenticated user session
    const session = await auth.api.getSession({
      headers: fromNodeHeaders(req.headers),
    });

    if (!session?.user?.email) {
      return res.status(401).json({
        success: false,
        message: "Please sign in first.",
      });
    }

    // Update only accounts that are awaiting role selection
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
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

run();

export default app;



