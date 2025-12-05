const express = require('express')
const cors = require ('cors')
const app = express()
require('dotenv').config();
const port = 3000
const { MongoClient, ServerApiVersion } = require('mongodb');

// middleware
app.use(express.json());
app.use(cors());

const uri = "mongodb+srv://simpleDBUserTwo:p86CRDCRKb1zJAID@cluster0.mzammbm.mongodb.net/?appName=Cluster0";
const stripe = require('stripe')(process.env.STRIPE_SECRET);

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});





async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
