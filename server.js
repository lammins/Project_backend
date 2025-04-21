const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const PORT = process.env.PORT || 5000;

require('dotenv').config();

const app = express();
app.use(cors({ origin: 'https://project-fontend-topaz.vercel.app/', credentials: true }));

app.use(express.json({ limit: '20mb' }));

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB error:', err));

// === Models === thay đổi User và Product nếu lưu trong collection khác (nên hỏi gpt để đổi)
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  brand: String,
  price: Number,
  image: String,
  description: String,
  nhu_cau: String,
}));

// === Middleware ===
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.user = decoded;
    next();
  });
};

// === Routes ===
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Thiếu thông tin' });
  if (await User.findOne({ username })) return res.status(400).json({ message: 'Tài khoản đã tồn tại' });
  const hashed = await bcrypt.hash(password, 10);
  await new User({ username, password: hashed }).save();
  res.sendStatus(201);
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.sendStatus(401);
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '30m' });
  res.json({ token });
});

app.get('/api/products', verifyToken, async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch {
    res.status(500).json({ message: 'Lỗi server' });
  }
});

app.get('/api/products/:id', verifyToken, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.sendStatus(404);
    res.json(product);
  } catch {
    res.sendStatus(400);
  }
});

app.get('/api/products', verifyToken, async (req, res) => {
  try {
    const searchTerm = req.query.search || '';
    const query = searchTerm
      ? { name: { $regex: searchTerm, $options: 'i' } }
      : {};

    const products = await Product.find(query);
    res.json(products);
  } catch {
    res.status(500).json({ message: 'Lỗi server' });
  }
});


app.post('/api/products', verifyToken, async (req, res) => {
  try {
    const { id, name, price } = req.body;
    if (!id || !name || !price) return res.status(400).json({ message: 'Thiếu thông tin bắt buộc' });
    if (await Product.findOne({ id })) return res.status(409).json({ message: 'ID đã tồn tại' });
    const newProduct = new Product(req.body);
    await newProduct.save();
    res.sendStatus(201);
  } catch {
    res.status(500).json({ message: 'Lỗi khi thêm sản phẩm' });
  }
});

app.put('/api/products/:id', verifyToken, async (req, res) => {
  try {
    await Product.findByIdAndUpdate(req.params.id, req.body);
    res.sendStatus(200);
  } catch {
    res.sendStatus(400);
  }
});

app.delete('/api/products/:id', verifyToken, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.sendStatus(200);
  } catch {
    res.sendStatus(400);
  }
});

//  Tìm ID lớn nhất trong một Category
app.get('/api/max-id/:category', verifyToken, async (req, res) => {
    try {
        const category = req.params.category;
        const prefix = `LAPTOP${category}`;
        const latestProduct = await Product.find({ id: { $regex: `^${prefix}` } })
            .sort({ id: -1 })
            .limit(1);

        if (latestProduct.length > 0) {
        const lastId = latestProduct[0].id;
        const numberPart = parseInt(lastId.slice(-4));
        return res.json({ lastNumber: numberPart });
        } else {
        return res.json({ lastNumber: 0 });
        }
    } catch (err) {
        res.status(500).json({ message: 'Lỗi khi tìm ID cao nhất' });
    }
});


app.listen(PORT, () => console.log(`🚀 Server is running at http://localhost:${PORT}`));

