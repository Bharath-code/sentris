/**
 * SENTRIS PRO — 3D Zero-Knowledge Cryptographic Hash Vault
 * Powered by Three.js (WebGL)
 * Features dual counter-rotating geometric shells, gyroscopic orbital rings,
 * dynamic point lighting, and smooth mouse inertia parallax.
 */

export class ThreeHashReactor {
  constructor(canvasElement) {
    this.canvas = canvasElement;
    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.coreGroup = null;
    this.innerMesh = null;
    this.outerWireframe = null;
    this.ring1 = null;
    this.ring2 = null;
    this.particleSystem = null;
    this.pointLight1 = null;
    this.pointLight2 = null;
    this.pulseActive = false;
    this.pulseTime = 0;
    this.targetMouseX = 0;
    this.targetMouseY = 0;
    this.currentMouseX = 0;
    this.currentMouseY = 0;
    this.animationId = null;

    if (this.canvas && window.THREE) {
      this.init();
    }
  }

  init() {
    const THREE = window.THREE;
    const width = this.canvas.clientWidth || 400;
    const height = this.canvas.clientHeight || 400;

    // 1. Scene & Perspective Camera
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    this.camera.position.z = 6.2;

    // 2. High-Performance Renderer
    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance'
    });
    this.renderer.setSize(width, height);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    this.coreGroup = new THREE.Group();
    this.scene.add(this.coreGroup);

    // 3. Inner Cryptographic Core (Octahedron with dark metallic material)
    const innerGeo = new THREE.OctahedronGeometry(1.4, 0);
    const innerMat = new THREE.MeshStandardMaterial({
      color: 0x0B0D14,
      roughness: 0.25,
      metalness: 0.85,
      wireframe: false
    });
    this.innerMesh = new THREE.Mesh(innerGeo, innerMat);
    this.coreGroup.add(this.innerMesh);

    // 4. Outer Faceted Wireframe (Icosahedron)
    const outerGeo = new THREE.IcosahedronGeometry(1.85, 1);
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x38BDF8,
      wireframe: true,
      transparent: true,
      opacity: 0.35
    });
    this.outerWireframe = new THREE.Mesh(outerGeo, outerMat);
    this.coreGroup.add(this.outerWireframe);

    // 5. Gyroscopic Orbital Rings
    const ringGeo1 = new THREE.TorusGeometry(2.3, 0.015, 16, 100);
    const ringMat1 = new THREE.MeshBasicMaterial({
      color: 0xFF5500,
      transparent: true,
      opacity: 0.4
    });
    this.ring1 = new THREE.Mesh(ringGeo1, ringMat1);
    this.ring1.rotation.x = Math.PI / 3;
    this.coreGroup.add(this.ring1);

    const ringGeo2 = new THREE.TorusGeometry(2.6, 0.012, 16, 100);
    const ringMat2 = new THREE.MeshBasicMaterial({
      color: 0x38BDF8,
      transparent: true,
      opacity: 0.25
    });
    this.ring2 = new THREE.Mesh(ringGeo2, ringMat2);
    this.ring2.rotation.y = Math.PI / 4;
    this.coreGroup.add(this.ring2);

    // 6. Particle Stream Field (140 Salted Hash Tokens)
    const count = 140;
    const posArray = new Float32Array(count * 3);
    const colArray = new Float32Array(count * 3);

    for (let i = 0; i < count; i++) {
      const radius = 2.1 + Math.random() * 1.8;
      const u = Math.random();
      const v = Math.random();
      const theta = u * 2.0 * Math.PI;
      const phi = Math.acos(2.0 * v - 1.0);
      const r = Math.cbrt(Math.random()) * 0.4 + radius;

      posArray[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      posArray[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      posArray[i * 3 + 2] = r * Math.cos(phi);

      if (Math.random() > 0.75) {
        // Cadmium Orange Alert Tokens
        colArray[i * 3] = 1.0;
        colArray[i * 3 + 1] = 0.33;
        colArray[i * 3 + 2] = 0.0;
      } else {
        // Cyan Cyber Tokens
        colArray[i * 3] = 0.22;
        colArray[i * 3 + 1] = 0.74;
        colArray[i * 3 + 2] = 0.97;
      }
    }

    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
    particleGeo.setAttribute('color', new THREE.BufferAttribute(colArray, 3));

    const particleMat = new THREE.PointsMaterial({
      size: 0.065,
      vertexColors: true,
      transparent: true,
      opacity: 0.85
    });

    this.particleSystem = new THREE.Points(particleGeo, particleMat);
    this.coreGroup.add(this.particleSystem);

    // 7. Dynamic Ambient & Point Lighting
    const ambientLight = new THREE.AmbientLight(0xFFFFFF, 0.4);
    this.scene.add(ambientLight);

    this.pointLight1 = new THREE.PointLight(0xFF5500, 2.8, 12);
    this.pointLight1.position.set(3, 2, 4);
    this.scene.add(this.pointLight1);

    this.pointLight2 = new THREE.PointLight(0x0284C7, 2.2, 12);
    this.pointLight2.position.set(-3, -2, 3);
    this.scene.add(this.pointLight2);

    // 8. Event Listeners & Loop
    this.bindEvents();
    this.animate();
  }

  bindEvents() {
    window.addEventListener('resize', () => {
      if (!this.canvas || !this.renderer) return;
      const w = this.canvas.clientWidth;
      const h = this.canvas.clientHeight;
      if (w && h) {
        this.camera.aspect = w / h;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(w, h);
      }
    });

    window.addEventListener('mousemove', (e) => {
      this.targetMouseX = (e.clientX / window.innerWidth - 0.5) * 0.8;
      this.targetMouseY = (e.clientY / window.innerHeight - 0.5) * 0.8;
    });

    this.canvas.addEventListener('click', () => {
      this.triggerScanPulse();
    });
  }

  triggerScanPulse() {
    this.pulseActive = true;
    this.pulseTime = 1.0;
  }

  animate() {
    this.animationId = requestAnimationFrame(() => this.animate());

    if (!this.renderer || !this.scene || !this.camera) return;

    // Smooth inertia camera tracking
    this.currentMouseX += (this.targetMouseX - this.currentMouseX) * 0.06;
    this.currentMouseY += (this.targetMouseY - this.currentMouseY) * 0.06;

    this.coreGroup.rotation.y = this.currentMouseX + performance.now() * 0.0004;
    this.coreGroup.rotation.x = this.currentMouseY + Math.sin(performance.now() * 0.0005) * 0.1;

    // Counter-rotation of inner core & rings
    if (this.innerMesh) {
      this.innerMesh.rotation.y -= 0.005;
      this.innerMesh.rotation.z += 0.003;
    }
    if (this.ring1) {
      this.ring1.rotation.z += 0.004;
    }
    if (this.ring2) {
      this.ring2.rotation.x -= 0.003;
    }
    if (this.particleSystem) {
      this.particleSystem.rotation.y += 0.002;
    }

    // Pulse effect on scan/click
    if (this.pulseActive) {
      const scale = 1.0 + Math.sin(this.pulseTime * Math.PI) * 0.2;
      this.coreGroup.scale.set(scale, scale, scale);
      this.pulseTime -= 0.035;
      if (this.pulseTime <= 0) {
        this.pulseActive = false;
        this.coreGroup.scale.set(1, 1, 1);
      }
    }

    this.renderer.render(this.scene, this.camera);
  }

  destroy() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
    }
    if (this.renderer) {
      this.renderer.dispose();
    }
  }
}
