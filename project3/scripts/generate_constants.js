const fs = require("fs");
const path = require("path");

// Generate sample constants (in production, use standardized constants)
function generateConstants() {
  const t = 3;
  const nRoundsF = 8;
  const nRoundsP = 57;
  const totalRounds = nRoundsF + nRoundsP;
  
  // Generate MDS matrix
  const mds = [];
  for (let i = 0; i < t; i++) {
    mds[i] = [];
    for (let j = 0; j < t; j++) {
      mds[i][j] = (i * t + j + 1) * 5; // Sample values
    }
  }
  
  // Generate round constants
  const roundConstants = [];
  for (let i = 0; i < totalRounds * t; i++) {
    roundConstants.push(i + 1); // Sample values
  }
  
  // Write to files
  const constantsDir = path.join(__dirname, "../circuits/constants");
  if (!fs.existsSync(constantsDir)) {
    fs.mkdirSync(constantsDir, { recursive: true });
  }
  
  fs.writeFileSync(
    path.join(constantsDir, "mds_matrix.json"),
    JSON.stringify(mds, null, 2)
  );
  
  fs.writeFileSync(
    path.join(constantsDir, "round_constants.json"),
    JSON.stringify(roundConstants, null, 2)
  );
  
  console.log("Constants generated successfully!");
}

generateConstants();
