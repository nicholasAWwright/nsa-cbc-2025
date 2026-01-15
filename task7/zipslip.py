import zipfile
import io

output_arcname = "...zip"

with zipfile.ZipFile(output_arcname, 'w') as zipf:
    zipf.write('net.axolotl.zippier.ZipFormat_7z.jar', arcname='formats/net.axolotl.zippier.ZipFormat_7z.jar')
    zipf.writestr('trigger.7z', 'Hello, this is file content!')

# Read and display the archive structure
print("Archive structure:")
print("-" * 40)
with zipfile.ZipFile(output_arcname, 'r') as zipf:
    for file_info in zipf.filelist:
        print(f"{file_info.filename:50} {file_info.file_size:>10} bytes")