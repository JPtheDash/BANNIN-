import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./Layout";
import Overview from "./pages/Overview";
import Findings from "./pages/Findings";
import Scanners from "./pages/Scanners";
import History from "./pages/History";
import Settings from "./pages/Settings";
import Scan from "./pages/Scan";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Overview />} />
          <Route path="/scan" element={<Scan />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/scanners" element={<Scanners />} />
          <Route path="/history" element={<History />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
