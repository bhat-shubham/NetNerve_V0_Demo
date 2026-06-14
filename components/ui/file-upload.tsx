import { cn } from "../../lib/utils";
import React, { useRef, useState } from "react";
import { motion } from "motion/react";
import { IconUpload } from "@tabler/icons-react";
import { useDropzone } from "react-dropzone";
import { CgFileRemove } from "react-icons/cg";
import { toast } from "react-hot-toast";
import { IoArrowRedoSharp} from "react-icons/io5";
import axios from "axios";
// import ResultPage from "./results";
const mainVariant = {
  initial: {
    x: 0,
    y: 0,
  },
  animate: {
    x: 20,
    y: -20,
    opacity: 0.9,
  },
};

const secondaryVariant = {
  initial: {
    opacity: 0,
  },
  animate: {
    opacity: 1,
  },
};

type FileUploadProps = {
  onChange?: (files: File[]) => void;
  setIsProcessed: React.Dispatch<React.SetStateAction<boolean>>;
  isProcessed?: boolean;
  setFile: React.Dispatch<React.SetStateAction<File | null>>;
  setProtocols: React.Dispatch<React.SetStateAction<string[]>>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setPacketData: React.Dispatch<React.SetStateAction<any[]>>;
  setTotalDataSize :React.Dispatch<React.SetStateAction<number[]>>;
  // setSummary:React.Dispatch<React.SetStateAction<string[]>>;
  setSummary: (summary: string) => void;
  // setUploadData: (data: unknown) => void;
};

export const FileUpload = ({ onChange, setIsProcessed, isProcessed , setFile , setPacketData , setProtocols , setTotalDataSize ,setSummary}: FileUploadProps) => {
  const [files, setFiles] = useState<File[]>([]);
  // const [summary, setSummary] = useState(null);
  const [progress, setProgress] = useState<number>(0);
  const isCancelledRef=useRef(false);
  // const [isProcessed, setIsProcessed] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const maxSize = 10 * 1024 * 1024;
  const [showComplete, setShowComplete] = useState(false);
  // const [protocols, setProtocols] = useState<string[]>([]);
  // const [packetData, setPacketData] = useState<any[]>([]);
  const controllerRef = useRef<AbortController | null>(null);
  // const [totalDataSize, setTotalDataSize] = useState<number>(0);

  const handleFileChange = (newFiles: File[]) => {
    if(newFiles.length>0){
      setFile(newFiles[0]);
    }
    setFiles((prevFiles) => [...prevFiles, ...newFiles]);
    // eslint-disable-next-line @typescript-eslint/no-unused-expressions
    onChange && onChange(newFiles);
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };
  
  // removing files
  const handleRemove = (fileToRemove: File) => {
    setFiles((prevFiles) => prevFiles.filter((file) => file !== fileToRemove));
    setProgress(0);
    isCancelledRef.current=true;
    setIsLoading(false);
    setFiles([]);
    setIsProcessed(false);
    controllerRef.current?.abort();
    toast.error("Operation Cancelled By User")

  };
  let controller = new AbortController();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const generateSummary = async (protocols: string[], packet_data: any[], total_data_size: number[], classification: any) => {
    try {
      const summaryRes = await fetch("http://localhost:8000/generate-summary/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocols,
          packet_data,
          total_data_size,
          classification,
        }),
      });

      if (!summaryRes.ok) {
        throw new Error("Failed to generate summary");
      }

      const summaryData = await summaryRes.json();
      return summaryData.summary[0];
    } catch (error) {
      console.error("Error generating summary:", error);
      throw error;
    }
  };

  const handleSubmit = async () => {
    if (files.length === 0) {
      toast.error("Please Upload A File Before Submitting");
      return;
    }

    const formData = new FormData();
    formData.append("file", files[0]);
    
    controller = new AbortController();
    isCancelledRef.current = false;
    setIsLoading(true);

    try {
      // axios request that handles both upload progress and processing
      const response = await axios({
        method: 'post',
        url: 'http://localhost:8000/uploadfile/',
        data: formData,
        signal: controller.signal,
        onUploadProgress: (axiosProgressEvent) => {
          if (typeof axiosProgressEvent.total === "number" && axiosProgressEvent.total > 0) {
            const percent = Math.round((axiosProgressEvent.loaded * 100) / axiosProgressEvent.total);
            setProgress(percent);
            if (percent === 100 && !isCancelledRef.current) {
              setShowComplete(true);
              toast.success("File Uploaded Successfully");
              setTimeout(() => setShowComplete(false), 1500);
            }
          }
        },
      });

      const { protocols, packet_data, total_data_size, classification } = response.data;

      setProtocols(protocols);
      setPacketData(packet_data);
      setTotalDataSize(total_data_size);
      
      const summaryPromise = generateSummary(protocols, packet_data, total_data_size, classification);
      
      const [summary] = await Promise.all([
        summaryPromise,
      ]);
      
      setSummary(summary);
      setIsProcessed(true);
      toast.success("File Processed Successfully");
      
    } catch (error) {
      console.error("Error during file processing:", error);
      if (!isCancelledRef.current) {
        toast.error(error instanceof Error ? error.message : "An error occurred");
      }
    } finally {
      if (!isCancelledRef.current) {
        setIsLoading(false);
      }
    }
  };

  const { getRootProps, isDragActive } = useDropzone({
    multiple: false,
    noClick: true,
    onDrop: handleFileChange,
    onDropRejected: (error) => {
      console.log(error);
      toast.error("Upload Failed,Try Again")
    },
  });
  const [inputKey, setInputKey] = useState(0);
  // Extension Check
  const allowedFileTypes = [".cap", ".pcap"];
  const fileExt = files.length > 0 ? files[0].name.split(".").pop()?.toLowerCase() : undefined;
  if (fileExt && !allowedFileTypes.includes(`.${fileExt}`)) {
    setInputKey(prev => prev + 1);
    setFiles([]); // Clear files on unsupported type
    toast.error("Only .cap or .pcap files are supported" ,{
      style:{
        borderRadius: "8px",
        backgroundColor: "#202F34",
        color: "#fff",
      }
    
    });
    return;
  }
  if (files.length > 0 && files[0].size > maxSize) {
    toast.error("Size Excedded,Upload a file<2MB");
    setFiles([]); // Clear files on size limit exceeded
    setInputKey(prev => prev + 1); // Reset input to allow re-upload
  }
  return (
    <div className="rounded-2xl mt-5 md:mt-0 border-green-400 w-full" {...getRootProps()}>
      <motion.div
      
        whileHover="animate"
        className="group/file block rounded-lg w-full relative overflow-hidden"
      >
        <input
          key={inputKey}
          ref={fileInputRef}
          id="file-upload-handle"
          type="file"
          accept=".cap,.pcap"
          onChange={(e) => handleFileChange(Array.from(e.target.files || []))}
          className="hidden"
        />
        <motion.div
        className="flex p-2 md:py-13 bg-black/5 border-t-green-500 border-l-green-500 border-r-blue-400 border-b-blue-400 backdrop-blur-xl border-white/10 rounded-2xl border-3 flex-col items-center justify-center">
          <p className="relative z-20 font-sans font-extrabold text-neutral-700 dark:text-white text-2xl">
            Upload Your <span className="text-green-400">Capture File</span> Here
          </p>
          <p className="text-center relative z-20 font-sans font-normal text-neutral-400 dark:text-neutral-400 text-base md:mt-5">
            <span className="hidden sm:inline">Drop Your Files Here or</span> Click to Upload ( .cap or .pcap ) <span className="block sm:hidden">Below 2MB Only</span>
          </p>
          <p className="hidden md:block font-sans font-normal text-neutral-400 mt-1" >* Only Files Below ~2MB Can Be Processed For Now</p>
          <div className="relative w-full mt-1 p-1 md:mt-5">
            {files.length > 0 &&
              files.map((file, idx) => (
                <motion.div
                  key={"file" + idx}
                  layoutId={idx === 0 ? "file-upload" : "file-upload-" + idx}
                  className={cn(
                    "relative z-40 bg-white/10 bg-clip-padding backdrop-blur-xl flex flex-col items-start justify-start p-4 mt-4 mx-auto rounded-lg",
                    "shadow-sm"
                  )}
                >
                  <div className="flex justify-between w-full items-center gap-4">
                    <motion.p
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      layout
                      className="text-xl text-neutral-700 dark:text-neutral-100 truncate max-w-xs"
                    >
                      {file.name}
                    </motion.p>
                    {/* <motion.p
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      layout
                      className="rounded-lg px-2 py-1 w-fit shrink-0 text-sm text-neutral-600 dark:bg-neutral-800 dark:text-white shadow-input"
                    >
                      {(file.size / (1024 * 1024)).toFixed(2)} MB
                    </motion.p> */}
                    <motion.div 
                    whileHover={{scale:1.2}} 
                    className="tooltip" 
                    data-tip="Remove"
                    whileTap={{ scale:0.5 }}
                    transition={{duration: 0.2,type: "spring",stiffness: 300,damping: 20,}}
                    >
                    <CgFileRemove
                      size={25}
                      onClick={() => handleRemove(file)}
                      className="cursor-pointer"
                    />
                    </motion.div>
                  </div>
                  <div className="rounded-2xl transition-all duration-500 z-10 mt-5 bg-gradient-to-r from-[#2c9f65] to-[#03afac] h-10 w-full"  style={{ width: `${progress}%` }}>
                  <button onClick={handleSubmit} disabled={isLoading} className="cursor-pointer gap-2 border-2 border-green-400 h-10 rounded-2xl flex items-center justify-center text-xl md:w-[26.5vw] w-[76.5vw]">
                    <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2 }}>
                      {isProcessed ? (
                        <motion.p
                        key="success"
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.1, type: "spring", stiffness: 500, damping: 20 }}
                        className="text-white">
                          ✅ File Processed Successfully!
                          </motion.p>
                          ) : isLoading ? (progress === 100 ? (showComplete ? (
                          <motion.p
                          key="done"
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ duration: 0.5 }}
                          className="text-white">
                            Uploading Done!
                            </motion.p>
                            ) : (
                            <motion.p
                            key="processing"
                            // initial={{ y:-10 }}
                            animate={{color: ["#ffffff", "#A1A1A1", "#ffffff"],}}
                            transition={{ duration: 2, ease:"easeInOut" ,repeat:Infinity }}
                            className="text-white">
                               Processing...
                              </motion.p>)
                              ) : (
                              <motion.p
                              key="uploading"
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              transition={{ duration: 0.5 }}
                              className="text-white">
                                 Uploading {progress}%
                                </motion.p>)
                                ) : (
                                <p> Analyze My Packet</p>
                                )}
                                </motion.div>
                    <div>
                    <IoArrowRedoSharp className=""/>
                    </div>
                  </button>
                  </div>
                </motion.div>
              ))}
            {!files.length && (
              <motion.div
              onClick={handleClick}
                layoutId="file-upload"
                variants={mainVariant}
                transition={{
                  type: "spring",
                  stiffness: 300,
                  damping: 20,
                  duration: 2,
                }}
                className={cn(
                  "cursor-pointer border border-dashed border-sky-400 md:shadow-[0_0_10px_rgba(70,700,128,0.9)] relative md:group-hover/file:shadow-2xl z-40  md:bg-white md:dark:bg-[#202F34] flex items-center justify-center h-32 mt-4 w-full max-w-full md:max-w-[8rem] mx-auto rounded-md",
                  // "shadow-[0px_10px_50px_rgba(0,0,0,0.1)]"
                )}
              >
                {isDragActive ? (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="text-neutral-600 flex flex-col items-center"
                  >
                    Drop it
                    <IconUpload className="h-6 w-6 text-neutral-600 dark:text-green-400" />
                  </motion.p>
                ) : (
                  <IconUpload className="h-9 stroke-3 w-9 text-neutral-600 dark:text-green-400" />
                )}
              </motion.div>
            )}

            {!files.length && (
              <motion.div
                variants={secondaryVariant}
                className="absolute opacity-0 border border-dashed border-sky-400 inset-0 z-30 bg-transparent flex items-center justify-center h-32 mt-4 w-full max-w-[8rem] mx-auto rounded-md"
              ></motion.div>
            )}
          </div>
        </motion.div>
      </motion.div>
      <p className="mt-2  justify-center">Need a .cap File To Test? Download One From:<span className=" text-green-400 underline"><a target="_" href="https://www.wireshark.org/download/automated/captures/"> WireShark</a></span></p>
    </div>
  );
};

// export function GridPattern() {
//   const columns = 15;
//   const rows = 11;
//   return (
//     <div className="flex bg-gradient-to-r from-[#44A08D] to-[#093637] shrink-0 flex-wrap justify-center items-center gap-x-px gap-y-px scale-110 p-0 rounded-md">
//       {Array.from({ length: rows }).map((_, row) =>
//         Array.from({ length: columns }).map((_, col) => {
//           const index = row * columns + col;
//           return (
//             <div
//               key={`${col}-${row}`}
//               className={`w-10 h-10 flex shrink-0 rounded-[2px] ${
//                 index % 2 === 0
//                   ? "bg-[#59B2A4]" // soft teal
//                   : "bg-[#0F3E3A] shadow-[inset_0_0_3px_rgba(255,255,255,0.1)]"
//               }`}
//             />
//           );
//         })
//       )}
//     </div>
//   );
// }