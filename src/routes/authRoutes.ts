import { Router } from 'express';
import { register, login } from '../controller/authController';
import { authenticateToken } from '../middleware/authMiddleware';

const router = Router();

router.post('/register', register);
router.post('/login', login);
router.get('/profile', authenticateToken, (req, res) => {
  const user = (req as any).user;
  res.json({ message: 'Perfil do usuário', user });
});

export default router;