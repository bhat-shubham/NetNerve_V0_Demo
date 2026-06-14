"use client";
import { FileUpload } from "../components/ui/file-upload";
import { Suspense, useRef , useState } from 'react';
import gsap from 'gsap';
import { useGSAP } from '@gsap/react';
import {SplitText} from "gsap/SplitText";
import ScrollSmoother from "gsap/ScrollSmoother";
import ScrollTrigger from "gsap/ScrollTrigger";
import Horizontalscroll from "../components/ui/horizontalscroll";
import Footer from "../components/ui/footer";
import Features from "../components/ui/features";
import ResultPage from "../components/ui/results";
import Link from "next/link";
import {AnimatedTestimonials,testimonials} from "../components/ui/animated-testimonials";
gsap.registerPlugin(useGSAP, SplitText, ScrollTrigger, ScrollSmoother);

export default function Home() {
  const [file,setFile] = useState<File | null>(null);
  const headline = useRef(null);
  const working = useRef<HTMLDivElement>(null);
  const para = useRef<HTMLParagraphElement>(null);
  const [isProcessed, setIsProcessed] = useState(false);
  const homeRef = useRef<HTMLDivElement>(null);
  const featureRef = useRef<HTMLDivElement>(null);
  const testimonialRef = useRef<HTMLDivElement>(null);
  const [protocols, setProtocols] = useState<string[]>([]);
  const [totalDataSize, setTotalDataSize] = useState<number[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [packetData, setPacketData] = useState<any[]>([]);
  const [summary, setSummary] = useState<string | null>(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  // const [uploadData, setUploadData] = useState<any>(null);

  const scrollToSection = (ref: React.RefObject<HTMLElement | null>) => {
    ref?.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useGSAP(() => {
    gsap.set(headline.current, { visibility: "visible" });
    gsap.set(para.current, { visibility: "visible" });
    let parasplit;
    const split = SplitText.create(headline.current, { type: "chars" });
    // paragraph split
    SplitText.create(para.current, { type: "words,lines",
      linesClass: "line",
      autoSplit: true,
      mask: "lines",
      onSplit: (self) => {
        parasplit = gsap.from(self.lines, {
          duration: 0.5,
          yPercent: 100,
          opacity: 0,
          stagger: 0.3,
          ease: "power2.out",
        });
        return parasplit;
      }
       });

    gsap.from(split.chars, {
      opacity: 0,
      x: 40,
      autoAlpha: 0, // handles opacity + visibility
      stagger: 0.04,
      duration: 0.4,
      ease: "ealstic.in",
    });
    gsap.from(featureRef.current, {
      scrollTrigger: featureRef.current,
      y: 200,
      stagger: 0.05,
      duration: 1,
      ease: "back.out(1.7)",
    });
    gsap.from(working.current, {
      scrollTrigger: working.current,
      filter: "blur(20px)",
      opacity: 0,
      duration: 2,
      ease: "power2.out",
    });
    gsap.to(".file-upload",{
      opacity: 1,
      duration: 0.5,
      // stagger: 0.05,
      ease: "power2.out",

    });
    // const smoother = ScrollSmoother.create({
    //   wrapper: "working",
    //   // content: ".h-screen",
    //   smooth:1,
    //   effects: true,
    //   normalizeScroll: true,
    //   smoothTouch: 0.1,
    // });
    // gsap.to("working", {
    //   xPercent: -100,
    //   ease: "none",
    //   scrollTrigger: {
    //     trigger: "working",
    //     scroller: smoother.wrapper(), // important!
    //     pin: true,
    //     scrub: 1,
    //     end: "+=1000", // adjust as needed
    //   }
    // });

    return () => {
        split.revert(); // clean up on unmount
      };
  });

  return (
    <>
    {
      isProcessed ? (
        <ResultPage file={file} protocols={protocols} packetData={packetData} totalDataSize={totalDataSize} summary={summary ?? ""}/>
      ) : (
    <div
      className="parent bg-gradient-to-r from-[#063747] to-[#0a466c] font-[Poppins,Georgia] font-extrabold">
  <div ref={homeRef} className="h-[100vh] relative flex-col align-middle items-center">
    
      <div className="py-2 md:py-5 navbar bg-transparent relative z-50">
        <div className="flex-1 flex-col items-center">
          <Link href="/" className="px-4 md:px-8 text-2xl md:text-3xl text-green-400">NetNerve</Link>
          <p className="md:block px-4 md:px-8 text-sm md:text-base">Network&apos;s nerve center, AI-powered.</p>
        </div>
        
        {/* Mobile menu button */}
        <div className="md:hidden flex items-center">
          <button 
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            className="text-green-400 hover:text-green-300 focus:outline-none mr-4"
            aria-label="Toggle menu"
          >
            <svg className="h-8 w-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              {isMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16m-7 6h7" />
              )}
            </svg>
          </button>
        </div>

        <div className="hidden md:flex">
          <ul className="menu menu-horizontal px-4 gap-4 md:gap-6 lg:gap-10">
            {['Home', 'Features', 'Working', 'Testimonials'].map((item) => (
              <li key={item}>
                <button 
                  onClick={() => {
                    const refs = {
                      'Home': homeRef,
                      'Features': featureRef,
                      'Working': working,
                      'Testimonials': testimonialRef
                    } as const;
                    const ref = refs[item as keyof typeof refs];
                    if (ref) scrollToSection(ref);
                    setIsMenuOpen(false);
                  }}
                  className="hover:text-green-400 transition-colors duration-200"
                >
                  {item}
                </button>
              </li>
            ))}
          </ul>
        </div>

        {/* ham menu */}
        {isMenuOpen && (
          <div className="absolute top-full left-0 right-0 bg-[#0a466c] md:hidden shadow-lg rounded-b-lg">
            <ul className="py-4 px-4 space-y-4">
              {['Home', 'Features', 'Working', 'Testimonials'].map((item) => (
                <li key={item}>
                  <button
                    onClick={() => {
                      const refs = {
                        'Home': homeRef,
                        'Features': featureRef,
                        'Working': working,
                        'Testimonials': testimonialRef
                      } as const;
                      const ref = refs[item as keyof typeof refs];
                      if (ref) scrollToSection(ref);
                      setIsMenuOpen(false);
                    }}
                    className="block w-full text-left px-4 py-2 text-lg hover:bg-[#063747] rounded-md transition-colors duration-200"
                  >
                    {item}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <div className="md:py-12 py-5 md:px-15 px-5 md:flex md:flex-row flex-col align-middle items-center justify-between">
        
        <div  className="h-1/2 md:w-1/2 text-cente w-full flex flex-col ">
          <h1 ref={headline} className="invisible md:text-6xl text-3xl text-green-200">
            Transform Raw <span className="text-green-400">Packet Data</span> into <span className="text-green-400">  Actionable Intelligence</span>
          </h1>
          <p ref={para} className="invisible mt-5 text-lg text-green-200">
            Our AI-driven platform transforms raw network packet captures into clear, actionable <span className="text-green-400">cybersecurity intelligence.</span> By applying advanced machine-learning models, it automatically analyzes traffic flows, extracts key metadata, and highlights anomalies or malicious behaviors <span className="text-green-400">without any manual effort.</span> <span className="hidden md:block">For Every capture files—cloud-based processing delivers real-time threat alerts and interactive visualizations of network traffic.Simply upload a capture and receive <span className="text-green-400"> easy-to-understand insights,</span> reports, and recommendations to help mitigate cyber threats.</span>
          </p>
        </div>
        <div className="w-full py-2 md:w-1/3 md:px-0 rounded-md ">
          <div className="file-upload opacity-0">
            <FileUpload 
            setIsProcessed={setIsProcessed} 
            isProcessed={isProcessed} 
            setFile={setFile} 
            setProtocols={setProtocols} 
            setPacketData={setPacketData}
            setTotalDataSize={setTotalDataSize}
            setSummary={setSummary} 
            // setUploadData={setUploadData}
            />          
          </div>
        </div>
      </div>
      </div>
      {/* <div className="py-10 flex justify-center items-center align-middle">
        <Suspense fallback={<p>Loading Demo...</p>}>
      <video width="1250" height="240" className="rounded-2xl hidden md:block" autoPlay playsInline loop muted>
        <source src="/Demo.mp4" type="video/mp4" />
        Your browser does not support the video tag.
      </video>
      </Suspense>
      </div> */}
      <Features featureRef={featureRef} />
      <div ref={working} className="h-[50x]">
       <Horizontalscroll />
      </div>
      <div ref={testimonialRef} className="h-[95vh] items-center justify-center align-middle">
        <h1 className="text-green-400 text-6xl text-center">
          Testimonials
        </h1>
      <AnimatedTestimonials testimonials={testimonials} />
      </div>
      <Footer />
      
      {/* background-image: linear-gradient(to right, var(--tw-gradient-stops)); */}
    </div>
      )}
      </>
  );
  
}
