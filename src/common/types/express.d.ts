// src/types/express.d.ts

import { User } from '../entities/user.entity'; // Asegúrate de que esta ruta sea correcta

declare global {
  namespace Express {
    interface Request {
      user?: User; // Extiende Request para incluir la propiedad user
    }
  }
}
