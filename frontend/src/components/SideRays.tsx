import React, { useEffect, useRef } from 'react';

export interface SideRaysProps {
  rayColor1?: string;
  rayColor2?: string;
  origin?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' | 'top' | 'left' | 'right' | 'bottom';
  speed?: number;
  intensity?: number;
  spread?: number;
  tilt?: number;
  saturation?: number;
  blend?: number;
  falloff?: number;
  opacity?: number;
  className?: string;
}

export const SideRays: React.FC<SideRaysProps> = ({
  rayColor1 = '#EAB308',
  rayColor2 = '#96c8ff',
  origin = 'top-right',
  speed = 1.9,
  intensity = 1.4,
  spread = 1.8,
  tilt = -21,
  saturation = 1.5,
  blend = 0.75,
  falloff = 1.6,
  opacity = 1.0,
  className = ''
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let time = 0;

    const parseColor = (hex: string) => {
      const clean = hex.replace('#', '');
      const num = parseInt(clean, 16);
      return {
        r: (num >> 16) & 255,
        g: (num >> 8) & 255,
        b: num & 255
      };
    };

    const c1 = parseColor(rayColor1);
    const c2 = parseColor(rayColor2);

    // Mixed blend color
    const blendColor = {
      r: Math.round(c1.r * (1 - blend) + c2.r * blend),
      g: Math.round(c1.g * (1 - blend) + c2.g * blend),
      b: Math.round(c1.b * (1 - blend) + c2.b * blend)
    };

    const resize = () => {
      const rect = canvas.parentElement?.getBoundingClientRect();
      const width = rect?.width || 1080;
      const height = rect?.height || 1080;
      canvas.width = width * window.devicePixelRatio;
      canvas.height = height * window.devicePixelRatio;
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    };

    resize();
    window.addEventListener('resize', resize);

    const render = () => {
      const width = canvas.width / window.devicePixelRatio;
      const height = canvas.height / window.devicePixelRatio;

      ctx.clearRect(0, 0, width, height);

      // Determine origin coordinates
      let ox = width;
      let oy = 0;
      if (origin === 'top-left') { ox = 0; oy = 0; }
      else if (origin === 'bottom-right') { ox = width; oy = height; }
      else if (origin === 'bottom-left') { ox = 0; oy = height; }
      else if (origin === 'top') { ox = width / 2; oy = 0; }
      else if (origin === 'bottom') { ox = width / 2; oy = height; }
      else if (origin === 'left') { ox = 0; oy = height / 2; }
      else if (origin === 'right') { ox = width; oy = height / 2; }

      const numRays = 28;
      const tiltRad = (tilt * Math.PI) / 180;
      const maxDist = Math.hypot(width, height) * falloff;

      time += 0.008 * speed;

      // Draw subtle ambient glow around origin
      const glowGrad = ctx.createRadialGradient(ox, oy, 0, ox, oy, maxDist * 0.4);
      glowGrad.addColorStop(0, `rgba(${c1.r}, ${c1.g}, ${c1.b}, ${0.25 * intensity * opacity})`);
      glowGrad.addColorStop(0.5, `rgba(${c2.r}, ${c2.g}, ${c2.b}, ${0.12 * intensity * opacity})`);
      glowGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = glowGrad;
      ctx.fillRect(0, 0, width, height);

      // Draw each volumetric ray
      for (let i = 0; i < numRays; i++) {
        const baseAngle = (i / numRays) * (Math.PI * 0.65 * spread) + tiltRad;
        const wave = Math.sin(time + i * 0.42) * 0.08 + Math.cos(time * 0.6 + i * 0.28) * 0.04;
        const angle = baseAngle + wave;

        const rayLength = maxDist * (0.75 + Math.sin(time * 0.4 + i) * 0.25);
        const rayWidth = (0.02 + Math.sin(time * 0.8 + i * 0.5) * 0.012) * spread;

        const x1 = ox + Math.cos(angle - rayWidth) * rayLength;
        const y1 = oy + Math.sin(angle - rayWidth) * rayLength;
        const x2 = ox + Math.cos(angle + rayWidth) * rayLength;
        const y2 = oy + Math.sin(angle + rayWidth) * rayLength;

        const rayGrad = ctx.createLinearGradient(ox, oy, (x1 + x2) / 2, (y1 + y2) / 2);

        const currentC = i % 2 === 0 ? c1 : blendColor;
        const rayOpacity = (0.08 + Math.sin(time + i * 0.6) * 0.04) * intensity * opacity;

        rayGrad.addColorStop(0, `rgba(${currentC.r}, ${currentC.g}, ${currentC.b}, ${rayOpacity * 1.8})`);
        rayGrad.addColorStop(0.35, `rgba(${c2.r}, ${c2.g}, ${c2.b}, ${rayOpacity * 0.85})`);
        rayGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');

        ctx.beginPath();
        ctx.moveTo(ox, oy);
        ctx.lineTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.closePath();

        ctx.fillStyle = rayGrad;
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', resize);
    };
  }, [rayColor1, rayColor2, origin, speed, intensity, spread, tilt, saturation, blend, falloff, opacity]);

  return (
    <canvas
      ref={canvasRef}
      className={`w-full h-full pointer-events-none ${className}`}
      style={{ display: 'block' }}
    />
  );
};
