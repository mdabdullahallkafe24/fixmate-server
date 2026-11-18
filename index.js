
import express from "express";
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
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    throw new Error(`${key} is missing from .env`);
  }
}

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

app.get("/api/services", async (req, res) => {
  try {
    const services = await serviceCollection
      .find({
        approvalStatus: "approved",
        isAvailable: true,
      })
      .sort({
        createdAt: -1,
      })
      .toArray();

    return res.status(200).json({
      success: true,
      message: "Available services fetched successfully.",
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
      !problemDescription.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Please provide all required booking information.",
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
      finalAmount: null,
      paymentStatus: "unpaid",

      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await bookingCollection.insertOne(newBooking);

    return res.status(201).json({
      success: true,
      message: "Your service booking has been submitted successfully.",
      booking: {
        ...newBooking,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Create booking error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to create booking. Please try again.",
    });
  }
});

// ==========================================
// CUSTOMER: GET MY BOOKINGS
// GET /api/bookings/my-bookings
// ==========================================

app.get("/api/bookings/my-bookings", async (req, res) => {
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
      .find({
        customerEmail: user.email,
      })
      .sort({
        createdAt: -1,
      })
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
// TECHNICIAN: UPDATE SERVICE
// PUT /api/services/:id
// ==========================================

app.put("/api/services/:id", async (req, res) => {
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

    const filter = {
      _id: new ObjectId(id),
      technicianEmail: user.email,
    };

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
      filter,
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
});

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

      console.log("Admin Get All Services API is configured!");
      console.log("Admin Approve/Reject Service API is configured!");
    });
  } catch (error) {
    console.error("Server startup failed:", error);
    process.exit(1);
  }
}

run();

export default app;
