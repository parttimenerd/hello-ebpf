/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with ib
 */
@java.lang.SuppressWarnings("unused")
public final class IbDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ib_prctl_set(Ptr<task_struct> task, @Unsigned long ctrl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_write_cmds"
  )
  public enum ib_uverbs_write_cmds implements Enum<ib_uverbs_write_cmds>, TypedEnum<ib_uverbs_write_cmds, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_USER_VERBS_CMD_GET_CONTEXT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_USER_VERBS_CMD_GET_CONTEXT"
    )
    IB_USER_VERBS_CMD_GET_CONTEXT,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_DEVICE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_USER_VERBS_CMD_QUERY_DEVICE"
    )
    IB_USER_VERBS_CMD_QUERY_DEVICE,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_PORT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_USER_VERBS_CMD_QUERY_PORT"
    )
    IB_USER_VERBS_CMD_QUERY_PORT,

    /**
     * {@code IB_USER_VERBS_CMD_ALLOC_PD = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_USER_VERBS_CMD_ALLOC_PD"
    )
    IB_USER_VERBS_CMD_ALLOC_PD,

    /**
     * {@code IB_USER_VERBS_CMD_DEALLOC_PD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_USER_VERBS_CMD_DEALLOC_PD"
    )
    IB_USER_VERBS_CMD_DEALLOC_PD,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_AH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_USER_VERBS_CMD_CREATE_AH"
    )
    IB_USER_VERBS_CMD_CREATE_AH,

    /**
     * {@code IB_USER_VERBS_CMD_MODIFY_AH = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_USER_VERBS_CMD_MODIFY_AH"
    )
    IB_USER_VERBS_CMD_MODIFY_AH,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_AH = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_USER_VERBS_CMD_QUERY_AH"
    )
    IB_USER_VERBS_CMD_QUERY_AH,

    /**
     * {@code IB_USER_VERBS_CMD_DESTROY_AH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_USER_VERBS_CMD_DESTROY_AH"
    )
    IB_USER_VERBS_CMD_DESTROY_AH,

    /**
     * {@code IB_USER_VERBS_CMD_REG_MR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_USER_VERBS_CMD_REG_MR"
    )
    IB_USER_VERBS_CMD_REG_MR,

    /**
     * {@code IB_USER_VERBS_CMD_REG_SMR = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_USER_VERBS_CMD_REG_SMR"
    )
    IB_USER_VERBS_CMD_REG_SMR,

    /**
     * {@code IB_USER_VERBS_CMD_REREG_MR = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_USER_VERBS_CMD_REREG_MR"
    )
    IB_USER_VERBS_CMD_REREG_MR,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_MR = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_USER_VERBS_CMD_QUERY_MR"
    )
    IB_USER_VERBS_CMD_QUERY_MR,

    /**
     * {@code IB_USER_VERBS_CMD_DEREG_MR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IB_USER_VERBS_CMD_DEREG_MR"
    )
    IB_USER_VERBS_CMD_DEREG_MR,

    /**
     * {@code IB_USER_VERBS_CMD_ALLOC_MW = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IB_USER_VERBS_CMD_ALLOC_MW"
    )
    IB_USER_VERBS_CMD_ALLOC_MW,

    /**
     * {@code IB_USER_VERBS_CMD_BIND_MW = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IB_USER_VERBS_CMD_BIND_MW"
    )
    IB_USER_VERBS_CMD_BIND_MW,

    /**
     * {@code IB_USER_VERBS_CMD_DEALLOC_MW = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_USER_VERBS_CMD_DEALLOC_MW"
    )
    IB_USER_VERBS_CMD_DEALLOC_MW,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL"
    )
    IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_CQ = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IB_USER_VERBS_CMD_CREATE_CQ"
    )
    IB_USER_VERBS_CMD_CREATE_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_RESIZE_CQ = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IB_USER_VERBS_CMD_RESIZE_CQ"
    )
    IB_USER_VERBS_CMD_RESIZE_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_DESTROY_CQ = 20}
     */
    @EnumMember(
        value = 20L,
        name = "IB_USER_VERBS_CMD_DESTROY_CQ"
    )
    IB_USER_VERBS_CMD_DESTROY_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_POLL_CQ = 21}
     */
    @EnumMember(
        value = 21L,
        name = "IB_USER_VERBS_CMD_POLL_CQ"
    )
    IB_USER_VERBS_CMD_POLL_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_PEEK_CQ = 22}
     */
    @EnumMember(
        value = 22L,
        name = "IB_USER_VERBS_CMD_PEEK_CQ"
    )
    IB_USER_VERBS_CMD_PEEK_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_REQ_NOTIFY_CQ = 23}
     */
    @EnumMember(
        value = 23L,
        name = "IB_USER_VERBS_CMD_REQ_NOTIFY_CQ"
    )
    IB_USER_VERBS_CMD_REQ_NOTIFY_CQ,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_QP = 24}
     */
    @EnumMember(
        value = 24L,
        name = "IB_USER_VERBS_CMD_CREATE_QP"
    )
    IB_USER_VERBS_CMD_CREATE_QP,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_QP = 25}
     */
    @EnumMember(
        value = 25L,
        name = "IB_USER_VERBS_CMD_QUERY_QP"
    )
    IB_USER_VERBS_CMD_QUERY_QP,

    /**
     * {@code IB_USER_VERBS_CMD_MODIFY_QP = 26}
     */
    @EnumMember(
        value = 26L,
        name = "IB_USER_VERBS_CMD_MODIFY_QP"
    )
    IB_USER_VERBS_CMD_MODIFY_QP,

    /**
     * {@code IB_USER_VERBS_CMD_DESTROY_QP = 27}
     */
    @EnumMember(
        value = 27L,
        name = "IB_USER_VERBS_CMD_DESTROY_QP"
    )
    IB_USER_VERBS_CMD_DESTROY_QP,

    /**
     * {@code IB_USER_VERBS_CMD_POST_SEND = 28}
     */
    @EnumMember(
        value = 28L,
        name = "IB_USER_VERBS_CMD_POST_SEND"
    )
    IB_USER_VERBS_CMD_POST_SEND,

    /**
     * {@code IB_USER_VERBS_CMD_POST_RECV = 29}
     */
    @EnumMember(
        value = 29L,
        name = "IB_USER_VERBS_CMD_POST_RECV"
    )
    IB_USER_VERBS_CMD_POST_RECV,

    /**
     * {@code IB_USER_VERBS_CMD_ATTACH_MCAST = 30}
     */
    @EnumMember(
        value = 30L,
        name = "IB_USER_VERBS_CMD_ATTACH_MCAST"
    )
    IB_USER_VERBS_CMD_ATTACH_MCAST,

    /**
     * {@code IB_USER_VERBS_CMD_DETACH_MCAST = 31}
     */
    @EnumMember(
        value = 31L,
        name = "IB_USER_VERBS_CMD_DETACH_MCAST"
    )
    IB_USER_VERBS_CMD_DETACH_MCAST,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_SRQ = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_USER_VERBS_CMD_CREATE_SRQ"
    )
    IB_USER_VERBS_CMD_CREATE_SRQ,

    /**
     * {@code IB_USER_VERBS_CMD_MODIFY_SRQ = 33}
     */
    @EnumMember(
        value = 33L,
        name = "IB_USER_VERBS_CMD_MODIFY_SRQ"
    )
    IB_USER_VERBS_CMD_MODIFY_SRQ,

    /**
     * {@code IB_USER_VERBS_CMD_QUERY_SRQ = 34}
     */
    @EnumMember(
        value = 34L,
        name = "IB_USER_VERBS_CMD_QUERY_SRQ"
    )
    IB_USER_VERBS_CMD_QUERY_SRQ,

    /**
     * {@code IB_USER_VERBS_CMD_DESTROY_SRQ = 35}
     */
    @EnumMember(
        value = 35L,
        name = "IB_USER_VERBS_CMD_DESTROY_SRQ"
    )
    IB_USER_VERBS_CMD_DESTROY_SRQ,

    /**
     * {@code IB_USER_VERBS_CMD_POST_SRQ_RECV = 36}
     */
    @EnumMember(
        value = 36L,
        name = "IB_USER_VERBS_CMD_POST_SRQ_RECV"
    )
    IB_USER_VERBS_CMD_POST_SRQ_RECV,

    /**
     * {@code IB_USER_VERBS_CMD_OPEN_XRCD = 37}
     */
    @EnumMember(
        value = 37L,
        name = "IB_USER_VERBS_CMD_OPEN_XRCD"
    )
    IB_USER_VERBS_CMD_OPEN_XRCD,

    /**
     * {@code IB_USER_VERBS_CMD_CLOSE_XRCD = 38}
     */
    @EnumMember(
        value = 38L,
        name = "IB_USER_VERBS_CMD_CLOSE_XRCD"
    )
    IB_USER_VERBS_CMD_CLOSE_XRCD,

    /**
     * {@code IB_USER_VERBS_CMD_CREATE_XSRQ = 39}
     */
    @EnumMember(
        value = 39L,
        name = "IB_USER_VERBS_CMD_CREATE_XSRQ"
    )
    IB_USER_VERBS_CMD_CREATE_XSRQ,

    /**
     * {@code IB_USER_VERBS_CMD_OPEN_QP = 40}
     */
    @EnumMember(
        value = 40L,
        name = "IB_USER_VERBS_CMD_OPEN_QP"
    )
    IB_USER_VERBS_CMD_OPEN_QP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_odp_general_cap_bits"
  )
  public enum ib_uverbs_odp_general_cap_bits implements Enum<ib_uverbs_odp_general_cap_bits>, TypedEnum<ib_uverbs_odp_general_cap_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_ODP_SUPPORT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_ODP_SUPPORT"
    )
    IB_UVERBS_ODP_SUPPORT,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_IMPLICIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_ODP_SUPPORT_IMPLICIT"
    )
    IB_UVERBS_ODP_SUPPORT_IMPLICIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_odp_transport_cap_bits"
  )
  public enum ib_uverbs_odp_transport_cap_bits implements Enum<ib_uverbs_odp_transport_cap_bits>, TypedEnum<ib_uverbs_odp_transport_cap_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_ODP_SUPPORT_SEND = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_ODP_SUPPORT_SEND"
    )
    IB_UVERBS_ODP_SUPPORT_SEND,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_RECV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_ODP_SUPPORT_RECV"
    )
    IB_UVERBS_ODP_SUPPORT_RECV,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_WRITE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_ODP_SUPPORT_WRITE"
    )
    IB_UVERBS_ODP_SUPPORT_WRITE,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_READ = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_ODP_SUPPORT_READ"
    )
    IB_UVERBS_ODP_SUPPORT_READ,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_ATOMIC = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_UVERBS_ODP_SUPPORT_ATOMIC"
    )
    IB_UVERBS_ODP_SUPPORT_ATOMIC,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_SRQ_RECV = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_UVERBS_ODP_SUPPORT_SRQ_RECV"
    )
    IB_UVERBS_ODP_SUPPORT_SRQ_RECV,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_FLUSH = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IB_UVERBS_ODP_SUPPORT_FLUSH"
    )
    IB_UVERBS_ODP_SUPPORT_FLUSH,

    /**
     * {@code IB_UVERBS_ODP_SUPPORT_ATOMIC_WRITE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IB_UVERBS_ODP_SUPPORT_ATOMIC_WRITE"
    )
    IB_UVERBS_ODP_SUPPORT_ATOMIC_WRITE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_wc_opcode"
  )
  public enum ib_uverbs_wc_opcode implements Enum<ib_uverbs_wc_opcode>, TypedEnum<ib_uverbs_wc_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_WC_SEND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_WC_SEND"
    )
    IB_UVERBS_WC_SEND,

    /**
     * {@code IB_UVERBS_WC_RDMA_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_WC_RDMA_WRITE"
    )
    IB_UVERBS_WC_RDMA_WRITE,

    /**
     * {@code IB_UVERBS_WC_RDMA_READ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_WC_RDMA_READ"
    )
    IB_UVERBS_WC_RDMA_READ,

    /**
     * {@code IB_UVERBS_WC_COMP_SWAP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_UVERBS_WC_COMP_SWAP"
    )
    IB_UVERBS_WC_COMP_SWAP,

    /**
     * {@code IB_UVERBS_WC_FETCH_ADD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_WC_FETCH_ADD"
    )
    IB_UVERBS_WC_FETCH_ADD,

    /**
     * {@code IB_UVERBS_WC_BIND_MW = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_UVERBS_WC_BIND_MW"
    )
    IB_UVERBS_WC_BIND_MW,

    /**
     * {@code IB_UVERBS_WC_LOCAL_INV = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_UVERBS_WC_LOCAL_INV"
    )
    IB_UVERBS_WC_LOCAL_INV,

    /**
     * {@code IB_UVERBS_WC_TSO = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_UVERBS_WC_TSO"
    )
    IB_UVERBS_WC_TSO,

    /**
     * {@code IB_UVERBS_WC_FLUSH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_WC_FLUSH"
    )
    IB_UVERBS_WC_FLUSH,

    /**
     * {@code IB_UVERBS_WC_ATOMIC_WRITE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_UVERBS_WC_ATOMIC_WRITE"
    )
    IB_UVERBS_WC_ATOMIC_WRITE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_create_qp_mask"
  )
  public enum ib_uverbs_create_qp_mask implements Enum<ib_uverbs_create_qp_mask>, TypedEnum<ib_uverbs_create_qp_mask, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_CREATE_QP_MASK_IND_TABLE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_CREATE_QP_MASK_IND_TABLE"
    )
    IB_UVERBS_CREATE_QP_MASK_IND_TABLE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_wr_opcode"
  )
  public enum ib_uverbs_wr_opcode implements Enum<ib_uverbs_wr_opcode>, TypedEnum<ib_uverbs_wr_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_WR_RDMA_WRITE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_WR_RDMA_WRITE"
    )
    IB_UVERBS_WR_RDMA_WRITE,

    /**
     * {@code IB_UVERBS_WR_RDMA_WRITE_WITH_IMM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_WR_RDMA_WRITE_WITH_IMM"
    )
    IB_UVERBS_WR_RDMA_WRITE_WITH_IMM,

    /**
     * {@code IB_UVERBS_WR_SEND = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_WR_SEND"
    )
    IB_UVERBS_WR_SEND,

    /**
     * {@code IB_UVERBS_WR_SEND_WITH_IMM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_UVERBS_WR_SEND_WITH_IMM"
    )
    IB_UVERBS_WR_SEND_WITH_IMM,

    /**
     * {@code IB_UVERBS_WR_RDMA_READ = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_WR_RDMA_READ"
    )
    IB_UVERBS_WR_RDMA_READ,

    /**
     * {@code IB_UVERBS_WR_ATOMIC_CMP_AND_SWP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_UVERBS_WR_ATOMIC_CMP_AND_SWP"
    )
    IB_UVERBS_WR_ATOMIC_CMP_AND_SWP,

    /**
     * {@code IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD"
    )
    IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD,

    /**
     * {@code IB_UVERBS_WR_LOCAL_INV = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_UVERBS_WR_LOCAL_INV"
    )
    IB_UVERBS_WR_LOCAL_INV,

    /**
     * {@code IB_UVERBS_WR_BIND_MW = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_WR_BIND_MW"
    )
    IB_UVERBS_WR_BIND_MW,

    /**
     * {@code IB_UVERBS_WR_SEND_WITH_INV = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_UVERBS_WR_SEND_WITH_INV"
    )
    IB_UVERBS_WR_SEND_WITH_INV,

    /**
     * {@code IB_UVERBS_WR_TSO = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_UVERBS_WR_TSO"
    )
    IB_UVERBS_WR_TSO,

    /**
     * {@code IB_UVERBS_WR_RDMA_READ_WITH_INV = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_UVERBS_WR_RDMA_READ_WITH_INV"
    )
    IB_UVERBS_WR_RDMA_READ_WITH_INV,

    /**
     * {@code IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP"
    )
    IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP,

    /**
     * {@code IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD"
    )
    IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD,

    /**
     * {@code IB_UVERBS_WR_FLUSH = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IB_UVERBS_WR_FLUSH"
    )
    IB_UVERBS_WR_FLUSH,

    /**
     * {@code IB_UVERBS_WR_ATOMIC_WRITE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IB_UVERBS_WR_ATOMIC_WRITE"
    )
    IB_UVERBS_WR_ATOMIC_WRITE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_device_cap_flags"
  )
  public enum ib_uverbs_device_cap_flags implements Enum<ib_uverbs_device_cap_flags>, TypedEnum<ib_uverbs_device_cap_flags, java.lang. @Unsigned Long> {
    /**
     * {@code IB_UVERBS_DEVICE_RESIZE_MAX_WR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_DEVICE_RESIZE_MAX_WR"
    )
    IB_UVERBS_DEVICE_RESIZE_MAX_WR,

    /**
     * {@code IB_UVERBS_DEVICE_BAD_PKEY_CNTR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_DEVICE_BAD_PKEY_CNTR"
    )
    IB_UVERBS_DEVICE_BAD_PKEY_CNTR,

    /**
     * {@code IB_UVERBS_DEVICE_BAD_QKEY_CNTR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_DEVICE_BAD_QKEY_CNTR"
    )
    IB_UVERBS_DEVICE_BAD_QKEY_CNTR,

    /**
     * {@code IB_UVERBS_DEVICE_RAW_MULTI = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_DEVICE_RAW_MULTI"
    )
    IB_UVERBS_DEVICE_RAW_MULTI,

    /**
     * {@code IB_UVERBS_DEVICE_AUTO_PATH_MIG = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_UVERBS_DEVICE_AUTO_PATH_MIG"
    )
    IB_UVERBS_DEVICE_AUTO_PATH_MIG,

    /**
     * {@code IB_UVERBS_DEVICE_CHANGE_PHY_PORT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_UVERBS_DEVICE_CHANGE_PHY_PORT"
    )
    IB_UVERBS_DEVICE_CHANGE_PHY_PORT,

    /**
     * {@code IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE"
    )
    IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE,

    /**
     * {@code IB_UVERBS_DEVICE_CURR_QP_STATE_MOD = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IB_UVERBS_DEVICE_CURR_QP_STATE_MOD"
    )
    IB_UVERBS_DEVICE_CURR_QP_STATE_MOD,

    /**
     * {@code IB_UVERBS_DEVICE_SHUTDOWN_PORT = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IB_UVERBS_DEVICE_SHUTDOWN_PORT"
    )
    IB_UVERBS_DEVICE_SHUTDOWN_PORT,

    /**
     * {@code IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT = 1024}
     */
    @EnumMember(
        value = 1024L,
        name = "IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT"
    )
    IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT,

    /**
     * {@code IB_UVERBS_DEVICE_SYS_IMAGE_GUID = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IB_UVERBS_DEVICE_SYS_IMAGE_GUID"
    )
    IB_UVERBS_DEVICE_SYS_IMAGE_GUID,

    /**
     * {@code IB_UVERBS_DEVICE_RC_RNR_NAK_GEN = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IB_UVERBS_DEVICE_RC_RNR_NAK_GEN"
    )
    IB_UVERBS_DEVICE_RC_RNR_NAK_GEN,

    /**
     * {@code IB_UVERBS_DEVICE_SRQ_RESIZE = 8192}
     */
    @EnumMember(
        value = 8192L,
        name = "IB_UVERBS_DEVICE_SRQ_RESIZE"
    )
    IB_UVERBS_DEVICE_SRQ_RESIZE,

    /**
     * {@code IB_UVERBS_DEVICE_N_NOTIFY_CQ = 16384}
     */
    @EnumMember(
        value = 16384L,
        name = "IB_UVERBS_DEVICE_N_NOTIFY_CQ"
    )
    IB_UVERBS_DEVICE_N_NOTIFY_CQ,

    /**
     * {@code IB_UVERBS_DEVICE_MEM_WINDOW = 131072}
     */
    @EnumMember(
        value = 131072L,
        name = "IB_UVERBS_DEVICE_MEM_WINDOW"
    )
    IB_UVERBS_DEVICE_MEM_WINDOW,

    /**
     * {@code IB_UVERBS_DEVICE_UD_IP_CSUM = 262144}
     */
    @EnumMember(
        value = 262144L,
        name = "IB_UVERBS_DEVICE_UD_IP_CSUM"
    )
    IB_UVERBS_DEVICE_UD_IP_CSUM,

    /**
     * {@code IB_UVERBS_DEVICE_XRC = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "IB_UVERBS_DEVICE_XRC"
    )
    IB_UVERBS_DEVICE_XRC,

    /**
     * {@code IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS = 2097152}
     */
    @EnumMember(
        value = 2097152L,
        name = "IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS"
    )
    IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS,

    /**
     * {@code IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A = 8388608}
     */
    @EnumMember(
        value = 8388608L,
        name = "IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A"
    )
    IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A,

    /**
     * {@code IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B = 16777216}
     */
    @EnumMember(
        value = 16777216L,
        name = "IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B"
    )
    IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B,

    /**
     * {@code IB_UVERBS_DEVICE_RC_IP_CSUM = 33554432}
     */
    @EnumMember(
        value = 33554432L,
        name = "IB_UVERBS_DEVICE_RC_IP_CSUM"
    )
    IB_UVERBS_DEVICE_RC_IP_CSUM,

    /**
     * {@code IB_UVERBS_DEVICE_RAW_IP_CSUM = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "IB_UVERBS_DEVICE_RAW_IP_CSUM"
    )
    IB_UVERBS_DEVICE_RAW_IP_CSUM,

    /**
     * {@code IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING = 536870912}
     */
    @EnumMember(
        value = 536870912L,
        name = "IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING"
    )
    IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING,

    /**
     * {@code IB_UVERBS_DEVICE_RAW_SCATTER_FCS = 17179869184}
     */
    @EnumMember(
        value = 17179869184L,
        name = "IB_UVERBS_DEVICE_RAW_SCATTER_FCS"
    )
    IB_UVERBS_DEVICE_RAW_SCATTER_FCS,

    /**
     * {@code IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING = 68719476736}
     */
    @EnumMember(
        value = 68719476736L,
        name = "IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING"
    )
    IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING,

    /**
     * {@code IB_UVERBS_DEVICE_FLUSH_GLOBAL = 274877906944}
     */
    @EnumMember(
        value = 274877906944L,
        name = "IB_UVERBS_DEVICE_FLUSH_GLOBAL"
    )
    IB_UVERBS_DEVICE_FLUSH_GLOBAL,

    /**
     * {@code IB_UVERBS_DEVICE_FLUSH_PERSISTENT = 549755813888}
     */
    @EnumMember(
        value = 549755813888L,
        name = "IB_UVERBS_DEVICE_FLUSH_PERSISTENT"
    )
    IB_UVERBS_DEVICE_FLUSH_PERSISTENT,

    /**
     * {@code IB_UVERBS_DEVICE_ATOMIC_WRITE = 1099511627776}
     */
    @EnumMember(
        value = 1099511627776L,
        name = "IB_UVERBS_DEVICE_ATOMIC_WRITE"
    )
    IB_UVERBS_DEVICE_ATOMIC_WRITE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_raw_packet_caps"
  )
  public enum ib_uverbs_raw_packet_caps implements Enum<ib_uverbs_raw_packet_caps>, TypedEnum<ib_uverbs_raw_packet_caps, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING"
    )
    IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING,

    /**
     * {@code IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS"
    )
    IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS,

    /**
     * {@code IB_UVERBS_RAW_PACKET_CAP_IP_CSUM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_RAW_PACKET_CAP_IP_CSUM"
    )
    IB_UVERBS_RAW_PACKET_CAP_IP_CSUM,

    /**
     * {@code IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP"
    )
    IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_access_flags"
  )
  public enum ib_uverbs_access_flags implements Enum<ib_uverbs_access_flags>, TypedEnum<ib_uverbs_access_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_ACCESS_LOCAL_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_ACCESS_LOCAL_WRITE"
    )
    IB_UVERBS_ACCESS_LOCAL_WRITE,

    /**
     * {@code IB_UVERBS_ACCESS_REMOTE_WRITE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_ACCESS_REMOTE_WRITE"
    )
    IB_UVERBS_ACCESS_REMOTE_WRITE,

    /**
     * {@code IB_UVERBS_ACCESS_REMOTE_READ = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_ACCESS_REMOTE_READ"
    )
    IB_UVERBS_ACCESS_REMOTE_READ,

    /**
     * {@code IB_UVERBS_ACCESS_REMOTE_ATOMIC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_ACCESS_REMOTE_ATOMIC"
    )
    IB_UVERBS_ACCESS_REMOTE_ATOMIC,

    /**
     * {@code IB_UVERBS_ACCESS_MW_BIND = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_UVERBS_ACCESS_MW_BIND"
    )
    IB_UVERBS_ACCESS_MW_BIND,

    /**
     * {@code IB_UVERBS_ACCESS_ZERO_BASED = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_UVERBS_ACCESS_ZERO_BASED"
    )
    IB_UVERBS_ACCESS_ZERO_BASED,

    /**
     * {@code IB_UVERBS_ACCESS_ON_DEMAND = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IB_UVERBS_ACCESS_ON_DEMAND"
    )
    IB_UVERBS_ACCESS_ON_DEMAND,

    /**
     * {@code IB_UVERBS_ACCESS_HUGETLB = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IB_UVERBS_ACCESS_HUGETLB"
    )
    IB_UVERBS_ACCESS_HUGETLB,

    /**
     * {@code IB_UVERBS_ACCESS_FLUSH_GLOBAL = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IB_UVERBS_ACCESS_FLUSH_GLOBAL"
    )
    IB_UVERBS_ACCESS_FLUSH_GLOBAL,

    /**
     * {@code IB_UVERBS_ACCESS_FLUSH_PERSISTENT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IB_UVERBS_ACCESS_FLUSH_PERSISTENT"
    )
    IB_UVERBS_ACCESS_FLUSH_PERSISTENT,

    /**
     * {@code IB_UVERBS_ACCESS_RELAXED_ORDERING = 1048576}
     */
    @EnumMember(
        value = 1048576L,
        name = "IB_UVERBS_ACCESS_RELAXED_ORDERING"
    )
    IB_UVERBS_ACCESS_RELAXED_ORDERING,

    /**
     * {@code IB_UVERBS_ACCESS_OPTIONAL_RANGE = 1072693248}
     */
    @EnumMember(
        value = 1072693248L,
        name = "IB_UVERBS_ACCESS_OPTIONAL_RANGE"
    )
    IB_UVERBS_ACCESS_OPTIONAL_RANGE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_srq_type"
  )
  public enum ib_uverbs_srq_type implements Enum<ib_uverbs_srq_type>, TypedEnum<ib_uverbs_srq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_SRQT_BASIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_SRQT_BASIC"
    )
    IB_UVERBS_SRQT_BASIC,

    /**
     * {@code IB_UVERBS_SRQT_XRC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_SRQT_XRC"
    )
    IB_UVERBS_SRQT_XRC,

    /**
     * {@code IB_UVERBS_SRQT_TM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_SRQT_TM"
    )
    IB_UVERBS_SRQT_TM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_wq_type"
  )
  public enum ib_uverbs_wq_type implements Enum<ib_uverbs_wq_type>, TypedEnum<ib_uverbs_wq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_WQT_RQ = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_WQT_RQ"
    )
    IB_UVERBS_WQT_RQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_wq_flags"
  )
  public enum ib_uverbs_wq_flags implements Enum<ib_uverbs_wq_flags>, TypedEnum<ib_uverbs_wq_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING"
    )
    IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING,

    /**
     * {@code IB_UVERBS_WQ_FLAGS_SCATTER_FCS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_WQ_FLAGS_SCATTER_FCS"
    )
    IB_UVERBS_WQ_FLAGS_SCATTER_FCS,

    /**
     * {@code IB_UVERBS_WQ_FLAGS_DELAY_DROP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_WQ_FLAGS_DELAY_DROP"
    )
    IB_UVERBS_WQ_FLAGS_DELAY_DROP,

    /**
     * {@code IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING"
    )
    IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_qp_type"
  )
  public enum ib_uverbs_qp_type implements Enum<ib_uverbs_qp_type>, TypedEnum<ib_uverbs_qp_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_QPT_RC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_QPT_RC"
    )
    IB_UVERBS_QPT_RC,

    /**
     * {@code IB_UVERBS_QPT_UC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_UVERBS_QPT_UC"
    )
    IB_UVERBS_QPT_UC,

    /**
     * {@code IB_UVERBS_QPT_UD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_UVERBS_QPT_UD"
    )
    IB_UVERBS_QPT_UD,

    /**
     * {@code IB_UVERBS_QPT_RAW_PACKET = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_UVERBS_QPT_RAW_PACKET"
    )
    IB_UVERBS_QPT_RAW_PACKET,

    /**
     * {@code IB_UVERBS_QPT_XRC_INI = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_UVERBS_QPT_XRC_INI"
    )
    IB_UVERBS_QPT_XRC_INI,

    /**
     * {@code IB_UVERBS_QPT_XRC_TGT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_UVERBS_QPT_XRC_TGT"
    )
    IB_UVERBS_QPT_XRC_TGT,

    /**
     * {@code IB_UVERBS_QPT_DRIVER = 255}
     */
    @EnumMember(
        value = 255L,
        name = "IB_UVERBS_QPT_DRIVER"
    )
    IB_UVERBS_QPT_DRIVER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_qp_create_flags"
  )
  public enum ib_uverbs_qp_create_flags implements Enum<ib_uverbs_qp_create_flags>, TypedEnum<ib_uverbs_qp_create_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK"
    )
    IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK,

    /**
     * {@code IB_UVERBS_QP_CREATE_SCATTER_FCS = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IB_UVERBS_QP_CREATE_SCATTER_FCS"
    )
    IB_UVERBS_QP_CREATE_SCATTER_FCS,

    /**
     * {@code IB_UVERBS_QP_CREATE_CVLAN_STRIPPING = 512}
     */
    @EnumMember(
        value = 512L,
        name = "IB_UVERBS_QP_CREATE_CVLAN_STRIPPING"
    )
    IB_UVERBS_QP_CREATE_CVLAN_STRIPPING,

    /**
     * {@code IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING = 2048}
     */
    @EnumMember(
        value = 2048L,
        name = "IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING"
    )
    IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING,

    /**
     * {@code IB_UVERBS_QP_CREATE_SQ_SIG_ALL = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IB_UVERBS_QP_CREATE_SQ_SIG_ALL"
    )
    IB_UVERBS_QP_CREATE_SQ_SIG_ALL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_gid_type"
  )
  public enum ib_uverbs_gid_type implements Enum<ib_uverbs_gid_type>, TypedEnum<ib_uverbs_gid_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_GID_TYPE_IB = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_GID_TYPE_IB"
    )
    IB_UVERBS_GID_TYPE_IB,

    /**
     * {@code IB_UVERBS_GID_TYPE_ROCE_V1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_GID_TYPE_ROCE_V1"
    )
    IB_UVERBS_GID_TYPE_ROCE_V1,

    /**
     * {@code IB_UVERBS_GID_TYPE_ROCE_V2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_GID_TYPE_ROCE_V2"
    )
    IB_UVERBS_GID_TYPE_ROCE_V2
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_poll_context"
  )
  public enum ib_poll_context implements Enum<ib_poll_context>, TypedEnum<ib_poll_context, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_POLL_SOFTIRQ = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_POLL_SOFTIRQ"
    )
    IB_POLL_SOFTIRQ,

    /**
     * {@code IB_POLL_WORKQUEUE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_POLL_WORKQUEUE"
    )
    IB_POLL_WORKQUEUE,

    /**
     * {@code IB_POLL_UNBOUND_WORKQUEUE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_POLL_UNBOUND_WORKQUEUE"
    )
    IB_POLL_UNBOUND_WORKQUEUE,

    /**
     * {@code IB_POLL_LAST_POOL_TYPE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_POLL_LAST_POOL_TYPE"
    )
    IB_POLL_LAST_POOL_TYPE,

    /**
     * {@code IB_POLL_DIRECT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_POLL_DIRECT"
    )
    IB_POLL_DIRECT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_security_struct"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_security_struct extends Struct {
    public @Unsigned int sid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_device extends Struct {
    public Ptr<device> dma_device;

    public ib_device_ops ops;

    public char @Size(64) [] name;

    public callback_head callback_head;

    public list_head event_handler_list;

    public rw_semaphore event_handler_rwsem;

    public @OriginalName("spinlock_t") spinlock qp_open_list_lock;

    public rw_semaphore client_data_rwsem;

    public xarray client_data;

    public mutex unregistration_lock;

    public rwlock_t cache_lock;

    public Ptr<ib_port_data> port_data;

    public int num_comp_vectors;

    @InlineUnion(34880)
    public device dev;

    @InlineUnion(34880)
    public ib_core_device coredev;

    public Ptr<attribute_group> @Size(4) [] groups;

    public char hw_stats_attr_index;

    public @Unsigned long uverbs_cmd_mask;

    public char @Size(64) [] node_desc;

    public @Unsigned @OriginalName("__be64") long node_guid;

    public @Unsigned int local_dma_lkey;

    public @Unsigned short is_switch;

    public @Unsigned short kverbs_provider;

    public @Unsigned short use_cq_dim;

    public char node_type;

    public @Unsigned int phys_port_cnt;

    public ib_device_attr attrs;

    public @OriginalName("hw_stats_device_data") Ptr<?> hw_stats_data;

    public rdmacg_device cg_device;

    public @Unsigned int index;

    public @OriginalName("spinlock_t") spinlock cq_pools_lock;

    public list_head @Size(3) [] cq_pools;

    public @OriginalName("rdma_restrack_root") Ptr<?> res;

    public @OriginalName("uapi_definition") Ptr<?> driver_def;

    public @OriginalName("refcount_t") refcount_struct refcount;

    public completion unreg_completion;

    public work_struct unregistration_work;

    public Ptr<rdma_link_ops> link_ops;

    public mutex compat_devs_mutex;

    public xarray compat_devs;

    public char @Size(16) [] iw_ifname;

    public @Unsigned int iw_driver_flags;

    public @Unsigned int lag_flags;

    public mutex subdev_lock;

    public list_head subdev_list_head;

    public rdma_nl_dev_type type;

    public Ptr<ib_device> parent;

    public list_head subdev_list;

    public rdma_nl_name_assign_type name_assign_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_signature_type"
  )
  public enum ib_signature_type implements Enum<ib_signature_type>, TypedEnum<ib_signature_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_SIG_TYPE_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_SIG_TYPE_NONE"
    )
    IB_SIG_TYPE_NONE,

    /**
     * {@code IB_SIG_TYPE_T10_DIF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_SIG_TYPE_T10_DIF"
    )
    IB_SIG_TYPE_T10_DIF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_t10_dif_bg_type"
  )
  public enum ib_t10_dif_bg_type implements Enum<ib_t10_dif_bg_type>, TypedEnum<ib_t10_dif_bg_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_T10DIF_CRC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_T10DIF_CRC"
    )
    IB_T10DIF_CRC,

    /**
     * {@code IB_T10DIF_CSUM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_T10DIF_CSUM"
    )
    IB_T10DIF_CSUM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_t10_dif_domain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_t10_dif_domain extends Struct {
    public ib_t10_dif_bg_type bg_type;

    public @Unsigned short pi_interval;

    public @Unsigned short bg;

    public @Unsigned short app_tag;

    public @Unsigned int ref_tag;

    public boolean ref_remap;

    public boolean app_escape;

    public boolean ref_escape;

    public @Unsigned short apptag_check_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_sig_domain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_sig_domain extends Struct {
    public ib_signature_type sig_type;

    public sig_of_ib_sig_domain sig;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_sig_attrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_sig_attrs extends Struct {
    public char check_mask;

    public ib_sig_domain mem;

    public ib_sig_domain wire;

    public int meta_length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_sig_err_type"
  )
  public enum ib_sig_err_type implements Enum<ib_sig_err_type>, TypedEnum<ib_sig_err_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_SIG_BAD_GUARD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_SIG_BAD_GUARD"
    )
    IB_SIG_BAD_GUARD,

    /**
     * {@code IB_SIG_BAD_REFTAG = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_SIG_BAD_REFTAG"
    )
    IB_SIG_BAD_REFTAG,

    /**
     * {@code IB_SIG_BAD_APPTAG = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_SIG_BAD_APPTAG"
    )
    IB_SIG_BAD_APPTAG
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_sig_err"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_sig_err extends Struct {
    public ib_sig_err_type err_type;

    public @Unsigned int expected;

    public @Unsigned int actual;

    public @Unsigned long sig_err_offset;

    public @Unsigned int key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_uverbs_advise_mr_advice"
  )
  public enum ib_uverbs_advise_mr_advice implements Enum<ib_uverbs_advise_mr_advice>, TypedEnum<ib_uverbs_advise_mr_advice, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH"
    )
    IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH,

    /**
     * {@code IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE"
    )
    IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE,

    /**
     * {@code IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT"
    )
    IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union ib_gid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_gid extends Union {
    public char @Size(16) [] raw;

    public global_of_ib_gid global;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_gid_type"
  )
  public enum ib_gid_type implements Enum<ib_gid_type>, TypedEnum<ib_gid_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_GID_TYPE_IB = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_GID_TYPE_IB"
    )
    IB_GID_TYPE_IB,

    /**
     * {@code IB_GID_TYPE_ROCE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_GID_TYPE_ROCE"
    )
    IB_GID_TYPE_ROCE,

    /**
     * {@code IB_GID_TYPE_ROCE_UDP_ENCAP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_GID_TYPE_ROCE_UDP_ENCAP"
    )
    IB_GID_TYPE_ROCE_UDP_ENCAP,

    /**
     * {@code IB_GID_TYPE_SIZE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_GID_TYPE_SIZE"
    )
    IB_GID_TYPE_SIZE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_gid_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_gid_attr extends Struct {
    public Ptr<net_device> ndev;

    public Ptr<ib_device> device;

    public ib_gid gid;

    public ib_gid_type gid_type;

    public @Unsigned short index;

    public @Unsigned int port_num;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_atomic_cap"
  )
  public enum ib_atomic_cap implements Enum<ib_atomic_cap>, TypedEnum<ib_atomic_cap, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_ATOMIC_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_ATOMIC_NONE"
    )
    IB_ATOMIC_NONE,

    /**
     * {@code IB_ATOMIC_HCA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_ATOMIC_HCA"
    )
    IB_ATOMIC_HCA,

    /**
     * {@code IB_ATOMIC_GLOB = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_ATOMIC_GLOB"
    )
    IB_ATOMIC_GLOB
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_odp_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_odp_caps extends Struct {
    public @Unsigned @OriginalName("uint64_t") long general_caps;

    public per_transport_caps_of_ib_odp_caps per_transport_caps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_rss_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_rss_caps extends Struct {
    public @Unsigned int supported_qpts;

    public @Unsigned int max_rwq_indirection_tables;

    public @Unsigned int max_rwq_indirection_table_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_tm_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_tm_caps extends Struct {
    public @Unsigned int max_rndv_hdr_size;

    public @Unsigned int max_num_tags;

    public @Unsigned int flags;

    public @Unsigned int max_ops;

    public @Unsigned int max_sge;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_cq_init_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_cq_init_attr extends Struct {
    public @Unsigned int cqe;

    public @Unsigned int comp_vector;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_cq_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_cq_caps extends Struct {
    public @Unsigned short max_cq_moderation_count;

    public @Unsigned short max_cq_moderation_period;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_dm_mr_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_dm_mr_attr extends Struct {
    public @Unsigned long length;

    public @Unsigned long offset;

    public @Unsigned int access_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_dm_alloc_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_dm_alloc_attr extends Struct {
    public @Unsigned long length;

    public @Unsigned int alignment;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_device_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_device_attr extends Struct {
    public @Unsigned long fw_ver;

    public @Unsigned @OriginalName("__be64") long sys_image_guid;

    public @Unsigned long max_mr_size;

    public @Unsigned long page_size_cap;

    public @Unsigned int vendor_id;

    public @Unsigned int vendor_part_id;

    public @Unsigned int hw_ver;

    public int max_qp;

    public int max_qp_wr;

    public @Unsigned long device_cap_flags;

    public @Unsigned long kernel_cap_flags;

    public int max_send_sge;

    public int max_recv_sge;

    public int max_sge_rd;

    public int max_cq;

    public int max_cqe;

    public int max_mr;

    public int max_pd;

    public int max_qp_rd_atom;

    public int max_ee_rd_atom;

    public int max_res_rd_atom;

    public int max_qp_init_rd_atom;

    public int max_ee_init_rd_atom;

    public ib_atomic_cap atomic_cap;

    public ib_atomic_cap masked_atomic_cap;

    public int max_ee;

    public int max_rdd;

    public int max_mw;

    public int max_raw_ipv6_qp;

    public int max_raw_ethy_qp;

    public int max_mcast_grp;

    public int max_mcast_qp_attach;

    public int max_total_mcast_qp_attach;

    public int max_ah;

    public int max_srq;

    public int max_srq_wr;

    public int max_srq_sge;

    public @Unsigned int max_fast_reg_page_list_len;

    public @Unsigned int max_pi_fast_reg_page_list_len;

    public @Unsigned short max_pkeys;

    public char local_ca_ack_delay;

    public int sig_prot_cap;

    public int sig_guard_cap;

    public ib_odp_caps odp_caps;

    public @Unsigned @OriginalName("uint64_t") long timestamp_mask;

    public @Unsigned @OriginalName("uint64_t") long hca_core_clock;

    public ib_rss_caps rss_caps;

    public @Unsigned int max_wq_type_rq;

    public @Unsigned int raw_packet_caps;

    public ib_tm_caps tm_caps;

    public ib_cq_caps cq_caps;

    public @Unsigned long max_dm_size;

    public @Unsigned int max_sgl_rd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_mtu"
  )
  public enum ib_mtu implements Enum<ib_mtu>, TypedEnum<ib_mtu, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_MTU_256 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_MTU_256"
    )
    IB_MTU_256,

    /**
     * {@code IB_MTU_512 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_MTU_512"
    )
    IB_MTU_512,

    /**
     * {@code IB_MTU_1024 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_MTU_1024"
    )
    IB_MTU_1024,

    /**
     * {@code IB_MTU_2048 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_MTU_2048"
    )
    IB_MTU_2048,

    /**
     * {@code IB_MTU_4096 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_MTU_4096"
    )
    IB_MTU_4096
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_port_state"
  )
  public enum ib_port_state implements Enum<ib_port_state>, TypedEnum<ib_port_state, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_PORT_NOP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_PORT_NOP"
    )
    IB_PORT_NOP,

    /**
     * {@code IB_PORT_DOWN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_PORT_DOWN"
    )
    IB_PORT_DOWN,

    /**
     * {@code IB_PORT_INIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_PORT_INIT"
    )
    IB_PORT_INIT,

    /**
     * {@code IB_PORT_ARMED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_PORT_ARMED"
    )
    IB_PORT_ARMED,

    /**
     * {@code IB_PORT_ACTIVE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_PORT_ACTIVE"
    )
    IB_PORT_ACTIVE,

    /**
     * {@code IB_PORT_ACTIVE_DEFER = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_PORT_ACTIVE_DEFER"
    )
    IB_PORT_ACTIVE_DEFER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_attr extends Struct {
    public @Unsigned long subnet_prefix;

    public ib_port_state state;

    public ib_mtu max_mtu;

    public ib_mtu active_mtu;

    public @Unsigned int phys_mtu;

    public int gid_tbl_len;

    public @Unsigned int ip_gids;

    public @Unsigned int port_cap_flags;

    public @Unsigned int max_msg_sz;

    public @Unsigned int bad_pkey_cntr;

    public @Unsigned int qkey_viol_cntr;

    public @Unsigned short pkey_tbl_len;

    public @Unsigned int sm_lid;

    public @Unsigned int lid;

    public char lmc;

    public char max_vl_num;

    public char sm_sl;

    public char subnet_timeout;

    public char init_type_reply;

    public char active_width;

    public @Unsigned short active_speed;

    public char phys_state;

    public @Unsigned short port_cap_flags2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_device_modify"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_device_modify extends Struct {
    public @Unsigned long sys_image_guid;

    public char @Size(64) [] node_desc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_modify"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_modify extends Struct {
    public @Unsigned int set_port_cap_mask;

    public @Unsigned int clr_port_cap_mask;

    public char init_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_event_type"
  )
  public enum ib_event_type implements Enum<ib_event_type>, TypedEnum<ib_event_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_EVENT_CQ_ERR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_EVENT_CQ_ERR"
    )
    IB_EVENT_CQ_ERR,

    /**
     * {@code IB_EVENT_QP_FATAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_EVENT_QP_FATAL"
    )
    IB_EVENT_QP_FATAL,

    /**
     * {@code IB_EVENT_QP_REQ_ERR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_EVENT_QP_REQ_ERR"
    )
    IB_EVENT_QP_REQ_ERR,

    /**
     * {@code IB_EVENT_QP_ACCESS_ERR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_EVENT_QP_ACCESS_ERR"
    )
    IB_EVENT_QP_ACCESS_ERR,

    /**
     * {@code IB_EVENT_COMM_EST = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_EVENT_COMM_EST"
    )
    IB_EVENT_COMM_EST,

    /**
     * {@code IB_EVENT_SQ_DRAINED = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_EVENT_SQ_DRAINED"
    )
    IB_EVENT_SQ_DRAINED,

    /**
     * {@code IB_EVENT_PATH_MIG = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_EVENT_PATH_MIG"
    )
    IB_EVENT_PATH_MIG,

    /**
     * {@code IB_EVENT_PATH_MIG_ERR = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_EVENT_PATH_MIG_ERR"
    )
    IB_EVENT_PATH_MIG_ERR,

    /**
     * {@code IB_EVENT_DEVICE_FATAL = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_EVENT_DEVICE_FATAL"
    )
    IB_EVENT_DEVICE_FATAL,

    /**
     * {@code IB_EVENT_PORT_ACTIVE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_EVENT_PORT_ACTIVE"
    )
    IB_EVENT_PORT_ACTIVE,

    /**
     * {@code IB_EVENT_PORT_ERR = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_EVENT_PORT_ERR"
    )
    IB_EVENT_PORT_ERR,

    /**
     * {@code IB_EVENT_LID_CHANGE = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_EVENT_LID_CHANGE"
    )
    IB_EVENT_LID_CHANGE,

    /**
     * {@code IB_EVENT_PKEY_CHANGE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_EVENT_PKEY_CHANGE"
    )
    IB_EVENT_PKEY_CHANGE,

    /**
     * {@code IB_EVENT_SM_CHANGE = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IB_EVENT_SM_CHANGE"
    )
    IB_EVENT_SM_CHANGE,

    /**
     * {@code IB_EVENT_SRQ_ERR = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IB_EVENT_SRQ_ERR"
    )
    IB_EVENT_SRQ_ERR,

    /**
     * {@code IB_EVENT_SRQ_LIMIT_REACHED = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IB_EVENT_SRQ_LIMIT_REACHED"
    )
    IB_EVENT_SRQ_LIMIT_REACHED,

    /**
     * {@code IB_EVENT_QP_LAST_WQE_REACHED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_EVENT_QP_LAST_WQE_REACHED"
    )
    IB_EVENT_QP_LAST_WQE_REACHED,

    /**
     * {@code IB_EVENT_CLIENT_REREGISTER = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IB_EVENT_CLIENT_REREGISTER"
    )
    IB_EVENT_CLIENT_REREGISTER,

    /**
     * {@code IB_EVENT_GID_CHANGE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IB_EVENT_GID_CHANGE"
    )
    IB_EVENT_GID_CHANGE,

    /**
     * {@code IB_EVENT_WQ_FATAL = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IB_EVENT_WQ_FATAL"
    )
    IB_EVENT_WQ_FATAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_cq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_cq extends Struct {
    public Ptr<ib_device> device;

    public @OriginalName("ib_ucq_object") Ptr<?> uobject;

    public @OriginalName("ib_comp_handler") Ptr<?> comp_handler;

    public Ptr<?> event_handler;

    public Ptr<?> cq_context;

    public int cqe;

    public @Unsigned int cqe_used;

    public atomic_t usecnt;

    public ib_poll_context poll_ctx;

    public Ptr<ib_wc> wc;

    public list_head pool_entry;

    @InlineUnion(34541)
    public irq_poll iop;

    @InlineUnion(34541)
    public work_struct work;

    public Ptr<workqueue_struct> comp_wq;

    public Ptr<dim> dim;

    public @OriginalName("ktime_t") long timestamp;

    public char interrupt;

    public char shared;

    public @Unsigned int comp_vector;

    public rdma_restrack_entry res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_qp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_qp extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_pd> pd;

    public Ptr<ib_cq> send_cq;

    public Ptr<ib_cq> recv_cq;

    public @OriginalName("spinlock_t") spinlock mr_lock;

    public int mrs_used;

    public list_head rdma_mrs;

    public list_head sig_mrs;

    public Ptr<ib_srq> srq;

    public completion srq_completion;

    public Ptr<ib_xrcd> xrcd;

    public list_head xrcd_list;

    public atomic_t usecnt;

    public list_head open_list;

    public Ptr<ib_qp> real_qp;

    public @OriginalName("ib_uqp_object") Ptr<?> uobject;

    public Ptr<?> event_handler;

    public Ptr<?> registered_event_handler;

    public Ptr<?> qp_context;

    public Ptr<ib_gid_attr> av_sgid_attr;

    public Ptr<ib_gid_attr> alt_path_sgid_attr;

    public @Unsigned int qp_num;

    public @Unsigned int max_write_sge;

    public @Unsigned int max_read_sge;

    public ib_qp_type qp_type;

    public Ptr<ib_rwq_ind_table> rwq_ind_tbl;

    public Ptr<ib_qp_security> qp_sec;

    public @Unsigned int port;

    public boolean integrity_en;

    public rdma_restrack_entry res;

    public Ptr<rdma_counter> counter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_srq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_srq extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_pd> pd;

    public @OriginalName("ib_usrq_object") Ptr<?> uobject;

    public Ptr<?> event_handler;

    public Ptr<?> srq_context;

    public ib_srq_type srq_type;

    public atomic_t usecnt;

    public ext_of_ib_srq ext;

    public rdma_restrack_entry res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_wq"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_wq extends Struct {
    public Ptr<ib_device> device;

    public @OriginalName("ib_uwq_object") Ptr<?> uobject;

    public Ptr<?> wq_context;

    public Ptr<?> event_handler;

    public Ptr<ib_pd> pd;

    public Ptr<ib_cq> cq;

    public @Unsigned int wq_num;

    public ib_wq_state state;

    public ib_wq_type wq_type;

    public atomic_t usecnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_event extends Struct {
    public Ptr<ib_device> device;

    public element_of_ib_event element;

    public ib_event_type event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_global_route"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_global_route extends Struct {
    public Ptr<ib_gid_attr> sgid_attr;

    public ib_gid dgid;

    public @Unsigned int flow_label;

    public char sgid_index;

    public char hop_limit;

    public char traffic_class;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_grh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_grh extends Struct {
    public @Unsigned @OriginalName("__be32") int version_tclass_flow;

    public @Unsigned @OriginalName("__be16") short paylen;

    public char next_hdr;

    public char hop_limit;

    public ib_gid sgid;

    public ib_gid dgid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_mr_type"
  )
  public enum ib_mr_type implements Enum<ib_mr_type>, TypedEnum<ib_mr_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_MR_TYPE_MEM_REG = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_MR_TYPE_MEM_REG"
    )
    IB_MR_TYPE_MEM_REG,

    /**
     * {@code IB_MR_TYPE_SG_GAPS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_MR_TYPE_SG_GAPS"
    )
    IB_MR_TYPE_SG_GAPS,

    /**
     * {@code IB_MR_TYPE_DM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_MR_TYPE_DM"
    )
    IB_MR_TYPE_DM,

    /**
     * {@code IB_MR_TYPE_USER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_MR_TYPE_USER"
    )
    IB_MR_TYPE_USER,

    /**
     * {@code IB_MR_TYPE_DMA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_MR_TYPE_DMA"
    )
    IB_MR_TYPE_DMA,

    /**
     * {@code IB_MR_TYPE_INTEGRITY = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_MR_TYPE_INTEGRITY"
    )
    IB_MR_TYPE_INTEGRITY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_mr_status"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_mr_status extends Struct {
    public @Unsigned int fail_status;

    public ib_sig_err sig_err;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_ah_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_ah_attr extends Struct {
    public @Unsigned short dlid;

    public char src_path_bits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_wc_status"
  )
  public enum ib_wc_status implements Enum<ib_wc_status>, TypedEnum<ib_wc_status, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_WC_SUCCESS = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_WC_SUCCESS"
    )
    IB_WC_SUCCESS,

    /**
     * {@code IB_WC_LOC_LEN_ERR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_WC_LOC_LEN_ERR"
    )
    IB_WC_LOC_LEN_ERR,

    /**
     * {@code IB_WC_LOC_QP_OP_ERR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_WC_LOC_QP_OP_ERR"
    )
    IB_WC_LOC_QP_OP_ERR,

    /**
     * {@code IB_WC_LOC_EEC_OP_ERR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_WC_LOC_EEC_OP_ERR"
    )
    IB_WC_LOC_EEC_OP_ERR,

    /**
     * {@code IB_WC_LOC_PROT_ERR = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_WC_LOC_PROT_ERR"
    )
    IB_WC_LOC_PROT_ERR,

    /**
     * {@code IB_WC_WR_FLUSH_ERR = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_WC_WR_FLUSH_ERR"
    )
    IB_WC_WR_FLUSH_ERR,

    /**
     * {@code IB_WC_MW_BIND_ERR = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_WC_MW_BIND_ERR"
    )
    IB_WC_MW_BIND_ERR,

    /**
     * {@code IB_WC_BAD_RESP_ERR = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_WC_BAD_RESP_ERR"
    )
    IB_WC_BAD_RESP_ERR,

    /**
     * {@code IB_WC_LOC_ACCESS_ERR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_WC_LOC_ACCESS_ERR"
    )
    IB_WC_LOC_ACCESS_ERR,

    /**
     * {@code IB_WC_REM_INV_REQ_ERR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_WC_REM_INV_REQ_ERR"
    )
    IB_WC_REM_INV_REQ_ERR,

    /**
     * {@code IB_WC_REM_ACCESS_ERR = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_WC_REM_ACCESS_ERR"
    )
    IB_WC_REM_ACCESS_ERR,

    /**
     * {@code IB_WC_REM_OP_ERR = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_WC_REM_OP_ERR"
    )
    IB_WC_REM_OP_ERR,

    /**
     * {@code IB_WC_RETRY_EXC_ERR = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_WC_RETRY_EXC_ERR"
    )
    IB_WC_RETRY_EXC_ERR,

    /**
     * {@code IB_WC_RNR_RETRY_EXC_ERR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IB_WC_RNR_RETRY_EXC_ERR"
    )
    IB_WC_RNR_RETRY_EXC_ERR,

    /**
     * {@code IB_WC_LOC_RDD_VIOL_ERR = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IB_WC_LOC_RDD_VIOL_ERR"
    )
    IB_WC_LOC_RDD_VIOL_ERR,

    /**
     * {@code IB_WC_REM_INV_RD_REQ_ERR = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IB_WC_REM_INV_RD_REQ_ERR"
    )
    IB_WC_REM_INV_RD_REQ_ERR,

    /**
     * {@code IB_WC_REM_ABORT_ERR = 16}
     */
    @EnumMember(
        value = 16L,
        name = "IB_WC_REM_ABORT_ERR"
    )
    IB_WC_REM_ABORT_ERR,

    /**
     * {@code IB_WC_INV_EECN_ERR = 17}
     */
    @EnumMember(
        value = 17L,
        name = "IB_WC_INV_EECN_ERR"
    )
    IB_WC_INV_EECN_ERR,

    /**
     * {@code IB_WC_INV_EEC_STATE_ERR = 18}
     */
    @EnumMember(
        value = 18L,
        name = "IB_WC_INV_EEC_STATE_ERR"
    )
    IB_WC_INV_EEC_STATE_ERR,

    /**
     * {@code IB_WC_FATAL_ERR = 19}
     */
    @EnumMember(
        value = 19L,
        name = "IB_WC_FATAL_ERR"
    )
    IB_WC_FATAL_ERR,

    /**
     * {@code IB_WC_RESP_TIMEOUT_ERR = 20}
     */
    @EnumMember(
        value = 20L,
        name = "IB_WC_RESP_TIMEOUT_ERR"
    )
    IB_WC_RESP_TIMEOUT_ERR,

    /**
     * {@code IB_WC_GENERAL_ERR = 21}
     */
    @EnumMember(
        value = 21L,
        name = "IB_WC_GENERAL_ERR"
    )
    IB_WC_GENERAL_ERR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_wc_opcode"
  )
  public enum ib_wc_opcode implements Enum<ib_wc_opcode>, TypedEnum<ib_wc_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_WC_SEND = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_WC_SEND"
    )
    IB_WC_SEND,

    /**
     * {@code IB_WC_RDMA_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_WC_RDMA_WRITE"
    )
    IB_WC_RDMA_WRITE,

    /**
     * {@code IB_WC_RDMA_READ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_WC_RDMA_READ"
    )
    IB_WC_RDMA_READ,

    /**
     * {@code IB_WC_COMP_SWAP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_WC_COMP_SWAP"
    )
    IB_WC_COMP_SWAP,

    /**
     * {@code IB_WC_FETCH_ADD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_WC_FETCH_ADD"
    )
    IB_WC_FETCH_ADD,

    /**
     * {@code IB_WC_BIND_MW = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_WC_BIND_MW"
    )
    IB_WC_BIND_MW,

    /**
     * {@code IB_WC_LOCAL_INV = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_WC_LOCAL_INV"
    )
    IB_WC_LOCAL_INV,

    /**
     * {@code IB_WC_LSO = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_WC_LSO"
    )
    IB_WC_LSO,

    /**
     * {@code IB_WC_ATOMIC_WRITE = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_WC_ATOMIC_WRITE"
    )
    IB_WC_ATOMIC_WRITE,

    /**
     * {@code IB_WC_REG_MR = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_WC_REG_MR"
    )
    IB_WC_REG_MR,

    /**
     * {@code IB_WC_MASKED_COMP_SWAP = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_WC_MASKED_COMP_SWAP"
    )
    IB_WC_MASKED_COMP_SWAP,

    /**
     * {@code IB_WC_MASKED_FETCH_ADD = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_WC_MASKED_FETCH_ADD"
    )
    IB_WC_MASKED_FETCH_ADD,

    /**
     * {@code IB_WC_FLUSH = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_WC_FLUSH"
    )
    IB_WC_FLUSH,

    /**
     * {@code IB_WC_RECV = 128}
     */
    @EnumMember(
        value = 128L,
        name = "IB_WC_RECV"
    )
    IB_WC_RECV,

    /**
     * {@code IB_WC_RECV_RDMA_WITH_IMM = 129}
     */
    @EnumMember(
        value = 129L,
        name = "IB_WC_RECV_RDMA_WITH_IMM"
    )
    IB_WC_RECV_RDMA_WITH_IMM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_cqe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_cqe extends Struct {
    public Ptr<?> done;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_wc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_wc extends Struct {
    @InlineUnion(34480)
    public @Unsigned long wr_id;

    @InlineUnion(34480)
    public Ptr<ib_cqe> wr_cqe;

    public ib_wc_status status;

    public ib_wc_opcode opcode;

    public @Unsigned int vendor_err;

    public @Unsigned int byte_len;

    public Ptr<ib_qp> qp;

    public ex_of_ib_send_wr_and_ex_of_ib_wc ex;

    public @Unsigned int src_qp;

    public @Unsigned int slid;

    public int wc_flags;

    public @Unsigned short pkey_index;

    public char sl;

    public char dlid_path_bits;

    public @Unsigned int port_num;

    public char @Size(6) [] smac;

    public @Unsigned short vlan_id;

    public char network_hdr_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_cq_notify_flags"
  )
  public enum ib_cq_notify_flags implements Enum<ib_cq_notify_flags>, TypedEnum<ib_cq_notify_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_CQ_SOLICITED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_CQ_SOLICITED"
    )
    IB_CQ_SOLICITED,

    /**
     * {@code IB_CQ_NEXT_COMP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_CQ_NEXT_COMP"
    )
    IB_CQ_NEXT_COMP,

    /**
     * {@code IB_CQ_SOLICITED_MASK = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_CQ_SOLICITED_MASK"
    )
    IB_CQ_SOLICITED_MASK,

    /**
     * {@code IB_CQ_REPORT_MISSED_EVENTS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_CQ_REPORT_MISSED_EVENTS"
    )
    IB_CQ_REPORT_MISSED_EVENTS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_srq_type"
  )
  public enum ib_srq_type implements Enum<ib_srq_type>, TypedEnum<ib_srq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_SRQT_BASIC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_SRQT_BASIC"
    )
    IB_SRQT_BASIC,

    /**
     * {@code IB_SRQT_XRC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_SRQT_XRC"
    )
    IB_SRQT_XRC,

    /**
     * {@code IB_SRQT_TM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_SRQT_TM"
    )
    IB_SRQT_TM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_srq_attr_mask"
  )
  public enum ib_srq_attr_mask implements Enum<ib_srq_attr_mask>, TypedEnum<ib_srq_attr_mask, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_SRQ_MAX_WR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_SRQ_MAX_WR"
    )
    IB_SRQ_MAX_WR,

    /**
     * {@code IB_SRQ_LIMIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_SRQ_LIMIT"
    )
    IB_SRQ_LIMIT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_srq_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_srq_attr extends Struct {
    public @Unsigned int max_wr;

    public @Unsigned int max_sge;

    public @Unsigned int srq_limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_xrcd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_xrcd extends Struct {
    public Ptr<ib_device> device;

    public atomic_t usecnt;

    public Ptr<inode> inode;

    public rw_semaphore tgt_qps_rwsem;

    public xarray tgt_qps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_srq_init_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_srq_init_attr extends Struct {
    public Ptr<?> event_handler;

    public Ptr<?> srq_context;

    public ib_srq_attr attr;

    public ib_srq_type srq_type;

    public ext_of_ib_srq_init_attr ext;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_qp_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_qp_cap extends Struct {
    public @Unsigned int max_send_wr;

    public @Unsigned int max_recv_wr;

    public @Unsigned int max_send_sge;

    public @Unsigned int max_recv_sge;

    public @Unsigned int max_inline_data;

    public @Unsigned int max_rdma_ctxs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_sig_type"
  )
  public enum ib_sig_type implements Enum<ib_sig_type>, TypedEnum<ib_sig_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_SIGNAL_ALL_WR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_SIGNAL_ALL_WR"
    )
    IB_SIGNAL_ALL_WR,

    /**
     * {@code IB_SIGNAL_REQ_WR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_SIGNAL_REQ_WR"
    )
    IB_SIGNAL_REQ_WR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_qp_type"
  )
  public enum ib_qp_type implements Enum<ib_qp_type>, TypedEnum<ib_qp_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_QPT_SMI = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_QPT_SMI"
    )
    IB_QPT_SMI,

    /**
     * {@code IB_QPT_GSI = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_QPT_GSI"
    )
    IB_QPT_GSI,

    /**
     * {@code IB_QPT_RC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_QPT_RC"
    )
    IB_QPT_RC,

    /**
     * {@code IB_QPT_UC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_QPT_UC"
    )
    IB_QPT_UC,

    /**
     * {@code IB_QPT_UD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_QPT_UD"
    )
    IB_QPT_UD,

    /**
     * {@code IB_QPT_RAW_IPV6 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_QPT_RAW_IPV6"
    )
    IB_QPT_RAW_IPV6,

    /**
     * {@code IB_QPT_RAW_ETHERTYPE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_QPT_RAW_ETHERTYPE"
    )
    IB_QPT_RAW_ETHERTYPE,

    /**
     * {@code IB_QPT_RAW_PACKET = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_QPT_RAW_PACKET"
    )
    IB_QPT_RAW_PACKET,

    /**
     * {@code IB_QPT_XRC_INI = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_QPT_XRC_INI"
    )
    IB_QPT_XRC_INI,

    /**
     * {@code IB_QPT_XRC_TGT = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_QPT_XRC_TGT"
    )
    IB_QPT_XRC_TGT,

    /**
     * {@code IB_QPT_MAX = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_QPT_MAX"
    )
    IB_QPT_MAX,

    /**
     * {@code IB_QPT_DRIVER = 255}
     */
    @EnumMember(
        value = 255L,
        name = "IB_QPT_DRIVER"
    )
    IB_QPT_DRIVER,

    /**
     * {@code IB_QPT_RESERVED1 = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IB_QPT_RESERVED1"
    )
    IB_QPT_RESERVED1,

    /**
     * {@code IB_QPT_RESERVED2 = 4097}
     */
    @EnumMember(
        value = 4097L,
        name = "IB_QPT_RESERVED2"
    )
    IB_QPT_RESERVED2,

    /**
     * {@code IB_QPT_RESERVED3 = 4098}
     */
    @EnumMember(
        value = 4098L,
        name = "IB_QPT_RESERVED3"
    )
    IB_QPT_RESERVED3,

    /**
     * {@code IB_QPT_RESERVED4 = 4099}
     */
    @EnumMember(
        value = 4099L,
        name = "IB_QPT_RESERVED4"
    )
    IB_QPT_RESERVED4,

    /**
     * {@code IB_QPT_RESERVED5 = 4100}
     */
    @EnumMember(
        value = 4100L,
        name = "IB_QPT_RESERVED5"
    )
    IB_QPT_RESERVED5,

    /**
     * {@code IB_QPT_RESERVED6 = 4101}
     */
    @EnumMember(
        value = 4101L,
        name = "IB_QPT_RESERVED6"
    )
    IB_QPT_RESERVED6,

    /**
     * {@code IB_QPT_RESERVED7 = 4102}
     */
    @EnumMember(
        value = 4102L,
        name = "IB_QPT_RESERVED7"
    )
    IB_QPT_RESERVED7,

    /**
     * {@code IB_QPT_RESERVED8 = 4103}
     */
    @EnumMember(
        value = 4103L,
        name = "IB_QPT_RESERVED8"
    )
    IB_QPT_RESERVED8,

    /**
     * {@code IB_QPT_RESERVED9 = 4104}
     */
    @EnumMember(
        value = 4104L,
        name = "IB_QPT_RESERVED9"
    )
    IB_QPT_RESERVED9,

    /**
     * {@code IB_QPT_RESERVED10 = 4105}
     */
    @EnumMember(
        value = 4105L,
        name = "IB_QPT_RESERVED10"
    )
    IB_QPT_RESERVED10
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_qp_init_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_qp_init_attr extends Struct {
    public Ptr<?> event_handler;

    public Ptr<?> qp_context;

    public Ptr<ib_cq> send_cq;

    public Ptr<ib_cq> recv_cq;

    public Ptr<ib_srq> srq;

    public Ptr<ib_xrcd> xrcd;

    public ib_qp_cap cap;

    public ib_sig_type sq_sig_type;

    public ib_qp_type qp_type;

    public @Unsigned int create_flags;

    public @Unsigned int port_num;

    public Ptr<ib_rwq_ind_table> rwq_ind_tbl;

    public @Unsigned int source_qpn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_rwq_ind_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_rwq_ind_table extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;

    public atomic_t usecnt;

    public @Unsigned int ind_tbl_num;

    public @Unsigned int log_ind_tbl_size;

    public Ptr<Ptr<ib_wq>> ind_tbl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_qp_state"
  )
  public enum ib_qp_state implements Enum<ib_qp_state>, TypedEnum<ib_qp_state, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_QPS_RESET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_QPS_RESET"
    )
    IB_QPS_RESET,

    /**
     * {@code IB_QPS_INIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_QPS_INIT"
    )
    IB_QPS_INIT,

    /**
     * {@code IB_QPS_RTR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_QPS_RTR"
    )
    IB_QPS_RTR,

    /**
     * {@code IB_QPS_RTS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_QPS_RTS"
    )
    IB_QPS_RTS,

    /**
     * {@code IB_QPS_SQD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_QPS_SQD"
    )
    IB_QPS_SQD,

    /**
     * {@code IB_QPS_SQE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_QPS_SQE"
    )
    IB_QPS_SQE,

    /**
     * {@code IB_QPS_ERR = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_QPS_ERR"
    )
    IB_QPS_ERR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_mig_state"
  )
  public enum ib_mig_state implements Enum<ib_mig_state>, TypedEnum<ib_mig_state, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_MIG_MIGRATED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_MIG_MIGRATED"
    )
    IB_MIG_MIGRATED,

    /**
     * {@code IB_MIG_REARM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_MIG_REARM"
    )
    IB_MIG_REARM,

    /**
     * {@code IB_MIG_ARMED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_MIG_ARMED"
    )
    IB_MIG_ARMED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_mw_type"
  )
  public enum ib_mw_type implements Enum<ib_mw_type>, TypedEnum<ib_mw_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_MW_TYPE_1 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_MW_TYPE_1"
    )
    IB_MW_TYPE_1,

    /**
     * {@code IB_MW_TYPE_2 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_MW_TYPE_2"
    )
    IB_MW_TYPE_2
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_qp_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_qp_attr extends Struct {
    public ib_qp_state qp_state;

    public ib_qp_state cur_qp_state;

    public ib_mtu path_mtu;

    public ib_mig_state path_mig_state;

    public @Unsigned int qkey;

    public @Unsigned int rq_psn;

    public @Unsigned int sq_psn;

    public @Unsigned int dest_qp_num;

    public int qp_access_flags;

    public ib_qp_cap cap;

    public rdma_ah_attr ah_attr;

    public rdma_ah_attr alt_ah_attr;

    public @Unsigned short pkey_index;

    public @Unsigned short alt_pkey_index;

    public char en_sqd_async_notify;

    public char sq_draining;

    public char max_rd_atomic;

    public char max_dest_rd_atomic;

    public char min_rnr_timer;

    public @Unsigned int port_num;

    public char timeout;

    public char retry_cnt;

    public char rnr_retry;

    public @Unsigned int alt_port_num;

    public char alt_timeout;

    public @Unsigned int rate_limit;

    public Ptr<net_device> xmit_slave;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_wr_opcode"
  )
  public enum ib_wr_opcode implements Enum<ib_wr_opcode>, TypedEnum<ib_wr_opcode, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_WR_RDMA_WRITE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_WR_RDMA_WRITE"
    )
    IB_WR_RDMA_WRITE,

    /**
     * {@code IB_WR_RDMA_WRITE_WITH_IMM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_WR_RDMA_WRITE_WITH_IMM"
    )
    IB_WR_RDMA_WRITE_WITH_IMM,

    /**
     * {@code IB_WR_SEND = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_WR_SEND"
    )
    IB_WR_SEND,

    /**
     * {@code IB_WR_SEND_WITH_IMM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_WR_SEND_WITH_IMM"
    )
    IB_WR_SEND_WITH_IMM,

    /**
     * {@code IB_WR_RDMA_READ = 4}
     */
    @EnumMember(
        value = 4L,
        name = "IB_WR_RDMA_READ"
    )
    IB_WR_RDMA_READ,

    /**
     * {@code IB_WR_ATOMIC_CMP_AND_SWP = 5}
     */
    @EnumMember(
        value = 5L,
        name = "IB_WR_ATOMIC_CMP_AND_SWP"
    )
    IB_WR_ATOMIC_CMP_AND_SWP,

    /**
     * {@code IB_WR_ATOMIC_FETCH_AND_ADD = 6}
     */
    @EnumMember(
        value = 6L,
        name = "IB_WR_ATOMIC_FETCH_AND_ADD"
    )
    IB_WR_ATOMIC_FETCH_AND_ADD,

    /**
     * {@code IB_WR_BIND_MW = 8}
     */
    @EnumMember(
        value = 8L,
        name = "IB_WR_BIND_MW"
    )
    IB_WR_BIND_MW,

    /**
     * {@code IB_WR_LSO = 10}
     */
    @EnumMember(
        value = 10L,
        name = "IB_WR_LSO"
    )
    IB_WR_LSO,

    /**
     * {@code IB_WR_SEND_WITH_INV = 9}
     */
    @EnumMember(
        value = 9L,
        name = "IB_WR_SEND_WITH_INV"
    )
    IB_WR_SEND_WITH_INV,

    /**
     * {@code IB_WR_RDMA_READ_WITH_INV = 11}
     */
    @EnumMember(
        value = 11L,
        name = "IB_WR_RDMA_READ_WITH_INV"
    )
    IB_WR_RDMA_READ_WITH_INV,

    /**
     * {@code IB_WR_LOCAL_INV = 7}
     */
    @EnumMember(
        value = 7L,
        name = "IB_WR_LOCAL_INV"
    )
    IB_WR_LOCAL_INV,

    /**
     * {@code IB_WR_MASKED_ATOMIC_CMP_AND_SWP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "IB_WR_MASKED_ATOMIC_CMP_AND_SWP"
    )
    IB_WR_MASKED_ATOMIC_CMP_AND_SWP,

    /**
     * {@code IB_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13}
     */
    @EnumMember(
        value = 13L,
        name = "IB_WR_MASKED_ATOMIC_FETCH_AND_ADD"
    )
    IB_WR_MASKED_ATOMIC_FETCH_AND_ADD,

    /**
     * {@code IB_WR_FLUSH = 14}
     */
    @EnumMember(
        value = 14L,
        name = "IB_WR_FLUSH"
    )
    IB_WR_FLUSH,

    /**
     * {@code IB_WR_ATOMIC_WRITE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "IB_WR_ATOMIC_WRITE"
    )
    IB_WR_ATOMIC_WRITE,

    /**
     * {@code IB_WR_REG_MR = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_WR_REG_MR"
    )
    IB_WR_REG_MR,

    /**
     * {@code IB_WR_REG_MR_INTEGRITY = 33}
     */
    @EnumMember(
        value = 33L,
        name = "IB_WR_REG_MR_INTEGRITY"
    )
    IB_WR_REG_MR_INTEGRITY,

    /**
     * {@code IB_WR_RESERVED1 = 240}
     */
    @EnumMember(
        value = 240L,
        name = "IB_WR_RESERVED1"
    )
    IB_WR_RESERVED1,

    /**
     * {@code IB_WR_RESERVED2 = 241}
     */
    @EnumMember(
        value = 241L,
        name = "IB_WR_RESERVED2"
    )
    IB_WR_RESERVED2,

    /**
     * {@code IB_WR_RESERVED3 = 242}
     */
    @EnumMember(
        value = 242L,
        name = "IB_WR_RESERVED3"
    )
    IB_WR_RESERVED3,

    /**
     * {@code IB_WR_RESERVED4 = 243}
     */
    @EnumMember(
        value = 243L,
        name = "IB_WR_RESERVED4"
    )
    IB_WR_RESERVED4,

    /**
     * {@code IB_WR_RESERVED5 = 244}
     */
    @EnumMember(
        value = 244L,
        name = "IB_WR_RESERVED5"
    )
    IB_WR_RESERVED5,

    /**
     * {@code IB_WR_RESERVED6 = 245}
     */
    @EnumMember(
        value = 245L,
        name = "IB_WR_RESERVED6"
    )
    IB_WR_RESERVED6,

    /**
     * {@code IB_WR_RESERVED7 = 246}
     */
    @EnumMember(
        value = 246L,
        name = "IB_WR_RESERVED7"
    )
    IB_WR_RESERVED7,

    /**
     * {@code IB_WR_RESERVED8 = 247}
     */
    @EnumMember(
        value = 247L,
        name = "IB_WR_RESERVED8"
    )
    IB_WR_RESERVED8,

    /**
     * {@code IB_WR_RESERVED9 = 248}
     */
    @EnumMember(
        value = 248L,
        name = "IB_WR_RESERVED9"
    )
    IB_WR_RESERVED9,

    /**
     * {@code IB_WR_RESERVED10 = 249}
     */
    @EnumMember(
        value = 249L,
        name = "IB_WR_RESERVED10"
    )
    IB_WR_RESERVED10
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_sge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_sge extends Struct {
    public @Unsigned long addr;

    public @Unsigned int length;

    public @Unsigned int lkey;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_send_wr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_send_wr extends Struct {
    public Ptr<ib_send_wr> next;

    @InlineUnion(34480)
    public @Unsigned long wr_id;

    @InlineUnion(34480)
    public Ptr<ib_cqe> wr_cqe;

    public Ptr<ib_sge> sg_list;

    public int num_sge;

    public ib_wr_opcode opcode;

    public int send_flags;

    public ex_of_ib_send_wr_and_ex_of_ib_wc ex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_ah"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_ah extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_pd> pd;

    public Ptr<ib_uobject> uobject;

    public Ptr<ib_gid_attr> sgid_attr;

    public rdma_ah_attr_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_mr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_mr extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_pd> pd;

    public @Unsigned int lkey;

    public @Unsigned int rkey;

    public @Unsigned long iova;

    public @Unsigned long length;

    public @Unsigned int page_size;

    public ib_mr_type type;

    public boolean need_inval;

    @InlineUnion(34569)
    public Ptr<ib_uobject> uobject;

    @InlineUnion(34569)
    public list_head qp_entry;

    public Ptr<ib_dm> dm;

    public Ptr<ib_sig_attrs> sig_attrs;

    public Ptr<ib_dmah> dmah;

    public rdma_restrack_entry res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_recv_wr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_recv_wr extends Struct {
    public Ptr<ib_recv_wr> next;

    @InlineUnion(34480)
    public @Unsigned long wr_id;

    @InlineUnion(34480)
    public Ptr<ib_cqe> wr_cqe;

    public Ptr<ib_sge> sg_list;

    public int num_sge;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_rdmacg_object"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_rdmacg_object extends Struct {
    public Ptr<rdma_cgroup> cg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_ucontext"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_ucontext extends Struct {
    public Ptr<ib_device> device;

    public @OriginalName("ib_uverbs_file") Ptr<?> ufile;

    public ib_rdmacg_object cg_obj;

    public @Unsigned long enabled_caps;

    public rdma_restrack_entry res;

    public xarray mmap_xa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_uobject"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_uobject extends Struct {
    public @Unsigned long user_handle;

    public @OriginalName("ib_uverbs_file") Ptr<?> ufile;

    public Ptr<ib_ucontext> context;

    public Ptr<?> object;

    public list_head list;

    public ib_rdmacg_object cg_obj;

    public int id;

    public kref ref;

    public atomic_t usecnt;

    public callback_head rcu;

    public @OriginalName("uverbs_api_object") Ptr<?> uapi_object;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_udata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_udata extends Struct {
    public Ptr<?> inbuf;

    public Ptr<?> outbuf;

    public @Unsigned long inlen;

    public @Unsigned long outlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_pd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_pd extends Struct {
    public @Unsigned int local_dma_lkey;

    public @Unsigned int flags;

    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;

    public atomic_t usecnt;

    public @Unsigned int unsafe_global_rkey;

    public Ptr<ib_mr> __internal_mr;

    public rdma_restrack_entry res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_wq_type"
  )
  public enum ib_wq_type implements Enum<ib_wq_type>, TypedEnum<ib_wq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_WQT_RQ = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_WQT_RQ"
    )
    IB_WQT_RQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_wq_state"
  )
  public enum ib_wq_state implements Enum<ib_wq_state>, TypedEnum<ib_wq_state, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_WQS_RESET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_WQS_RESET"
    )
    IB_WQS_RESET,

    /**
     * {@code IB_WQS_RDY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_WQS_RDY"
    )
    IB_WQS_RDY,

    /**
     * {@code IB_WQS_ERR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_WQS_ERR"
    )
    IB_WQS_ERR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_wq_init_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_wq_init_attr extends Struct {
    public Ptr<?> wq_context;

    public ib_wq_type wq_type;

    public @Unsigned int max_wr;

    public @Unsigned int max_sge;

    public Ptr<ib_cq> cq;

    public Ptr<?> event_handler;

    public @Unsigned int create_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_wq_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_wq_attr extends Struct {
    public ib_wq_state wq_state;

    public ib_wq_state curr_wq_state;

    public @Unsigned int flags;

    public @Unsigned int flags_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_rwq_ind_table_init_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_rwq_ind_table_init_attr extends Struct {
    public @Unsigned int log_ind_tbl_size;

    public Ptr<Ptr<ib_wq>> ind_tbl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_pkey"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_pkey extends Struct {
    public port_pkey_state state;

    public @Unsigned short pkey_index;

    public @Unsigned int port_num;

    public list_head qp_list;

    public list_head to_error_list;

    public Ptr<ib_qp_security> sec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_qp_security"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_qp_security extends Struct {
    public Ptr<ib_qp> qp;

    public Ptr<ib_device> dev;

    public mutex mutex;

    public Ptr<ib_ports_pkeys> ports_pkeys;

    public list_head shared_qp_list;

    public Ptr<?> security;

    public boolean destroying;

    public atomic_t error_list_count;

    public completion error_complete;

    public int error_comps_pending;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_ports_pkeys"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_ports_pkeys extends Struct {
    public ib_port_pkey main;

    public ib_port_pkey alt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_dm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_dm extends Struct {
    public Ptr<ib_device> device;

    public @Unsigned int length;

    public @Unsigned int flags;

    public Ptr<ib_uobject> uobject;

    public atomic_t usecnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_dmah"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_dmah extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;

    public rdma_restrack_entry res;

    public @Unsigned int cpu_id;

    public tph_mem_type mem_type;

    public atomic_t usecnt;

    public char ph;

    public char valid_fields;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_mw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_mw extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_pd> pd;

    public Ptr<ib_uobject> uobject;

    public @Unsigned int rkey;

    public ib_mw_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_flow_attr_type"
  )
  public enum ib_flow_attr_type implements Enum<ib_flow_attr_type>, TypedEnum<ib_flow_attr_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_FLOW_ATTR_NORMAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_FLOW_ATTR_NORMAL"
    )
    IB_FLOW_ATTR_NORMAL,

    /**
     * {@code IB_FLOW_ATTR_ALL_DEFAULT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_FLOW_ATTR_ALL_DEFAULT"
    )
    IB_FLOW_ATTR_ALL_DEFAULT,

    /**
     * {@code IB_FLOW_ATTR_MC_DEFAULT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "IB_FLOW_ATTR_MC_DEFAULT"
    )
    IB_FLOW_ATTR_MC_DEFAULT,

    /**
     * {@code IB_FLOW_ATTR_SNIFFER = 3}
     */
    @EnumMember(
        value = 3L,
        name = "IB_FLOW_ATTR_SNIFFER"
    )
    IB_FLOW_ATTR_SNIFFER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_flow_spec_type"
  )
  public enum ib_flow_spec_type implements Enum<ib_flow_spec_type>, TypedEnum<ib_flow_spec_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_FLOW_SPEC_ETH = 32}
     */
    @EnumMember(
        value = 32L,
        name = "IB_FLOW_SPEC_ETH"
    )
    IB_FLOW_SPEC_ETH,

    /**
     * {@code IB_FLOW_SPEC_IB = 34}
     */
    @EnumMember(
        value = 34L,
        name = "IB_FLOW_SPEC_IB"
    )
    IB_FLOW_SPEC_IB,

    /**
     * {@code IB_FLOW_SPEC_IPV4 = 48}
     */
    @EnumMember(
        value = 48L,
        name = "IB_FLOW_SPEC_IPV4"
    )
    IB_FLOW_SPEC_IPV4,

    /**
     * {@code IB_FLOW_SPEC_IPV6 = 49}
     */
    @EnumMember(
        value = 49L,
        name = "IB_FLOW_SPEC_IPV6"
    )
    IB_FLOW_SPEC_IPV6,

    /**
     * {@code IB_FLOW_SPEC_ESP = 52}
     */
    @EnumMember(
        value = 52L,
        name = "IB_FLOW_SPEC_ESP"
    )
    IB_FLOW_SPEC_ESP,

    /**
     * {@code IB_FLOW_SPEC_TCP = 64}
     */
    @EnumMember(
        value = 64L,
        name = "IB_FLOW_SPEC_TCP"
    )
    IB_FLOW_SPEC_TCP,

    /**
     * {@code IB_FLOW_SPEC_UDP = 65}
     */
    @EnumMember(
        value = 65L,
        name = "IB_FLOW_SPEC_UDP"
    )
    IB_FLOW_SPEC_UDP,

    /**
     * {@code IB_FLOW_SPEC_VXLAN_TUNNEL = 80}
     */
    @EnumMember(
        value = 80L,
        name = "IB_FLOW_SPEC_VXLAN_TUNNEL"
    )
    IB_FLOW_SPEC_VXLAN_TUNNEL,

    /**
     * {@code IB_FLOW_SPEC_GRE = 81}
     */
    @EnumMember(
        value = 81L,
        name = "IB_FLOW_SPEC_GRE"
    )
    IB_FLOW_SPEC_GRE,

    /**
     * {@code IB_FLOW_SPEC_MPLS = 96}
     */
    @EnumMember(
        value = 96L,
        name = "IB_FLOW_SPEC_MPLS"
    )
    IB_FLOW_SPEC_MPLS,

    /**
     * {@code IB_FLOW_SPEC_INNER = 256}
     */
    @EnumMember(
        value = 256L,
        name = "IB_FLOW_SPEC_INNER"
    )
    IB_FLOW_SPEC_INNER,

    /**
     * {@code IB_FLOW_SPEC_ACTION_TAG = 4096}
     */
    @EnumMember(
        value = 4096L,
        name = "IB_FLOW_SPEC_ACTION_TAG"
    )
    IB_FLOW_SPEC_ACTION_TAG,

    /**
     * {@code IB_FLOW_SPEC_ACTION_DROP = 4097}
     */
    @EnumMember(
        value = 4097L,
        name = "IB_FLOW_SPEC_ACTION_DROP"
    )
    IB_FLOW_SPEC_ACTION_DROP,

    /**
     * {@code IB_FLOW_SPEC_ACTION_HANDLE = 4098}
     */
    @EnumMember(
        value = 4098L,
        name = "IB_FLOW_SPEC_ACTION_HANDLE"
    )
    IB_FLOW_SPEC_ACTION_HANDLE,

    /**
     * {@code IB_FLOW_SPEC_ACTION_COUNT = 4099}
     */
    @EnumMember(
        value = 4099L,
        name = "IB_FLOW_SPEC_ACTION_COUNT"
    )
    IB_FLOW_SPEC_ACTION_COUNT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_eth_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_eth_filter extends Struct {
    public char @Size(6) [] dst_mac;

    public char @Size(6) [] src_mac;

    public @Unsigned @OriginalName("__be16") short ether_type;

    public @Unsigned @OriginalName("__be16") short vlan_tag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_eth"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_eth extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_eth_filter val;

    public ib_flow_eth_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_ib_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_ib_filter extends Struct {
    public @Unsigned @OriginalName("__be16") short dlid;

    public char sl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_ib"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_ib extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_ib_filter val;

    public ib_flow_ib_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_ipv4_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_ipv4_filter extends Struct {
    public @Unsigned @OriginalName("__be32") int src_ip;

    public @Unsigned @OriginalName("__be32") int dst_ip;

    public char proto;

    public char tos;

    public char ttl;

    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_ipv4"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_ipv4 extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_ipv4_filter val;

    public ib_flow_ipv4_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_ipv6_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_ipv6_filter extends Struct {
    public char @Size(16) [] src_ip;

    public char @Size(16) [] dst_ip;

    public @Unsigned @OriginalName("__be32") int flow_label;

    public char next_hdr;

    public char traffic_class;

    public char hop_limit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_ipv6"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_ipv6 extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_ipv6_filter val;

    public ib_flow_ipv6_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_tcp_udp_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_tcp_udp_filter extends Struct {
    public @Unsigned @OriginalName("__be16") short dst_port;

    public @Unsigned @OriginalName("__be16") short src_port;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_tcp_udp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_tcp_udp extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_tcp_udp_filter val;

    public ib_flow_tcp_udp_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_tunnel_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_tunnel_filter extends Struct {
    public @Unsigned @OriginalName("__be32") int tunnel_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_tunnel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_tunnel extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_tunnel_filter val;

    public ib_flow_tunnel_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_esp_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_esp_filter extends Struct {
    public @Unsigned @OriginalName("__be32") int spi;

    public @Unsigned @OriginalName("__be32") int seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_esp"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_esp extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_esp_filter val;

    public ib_flow_esp_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_gre_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_gre_filter extends Struct {
    public @Unsigned @OriginalName("__be16") short c_ks_res0_ver;

    public @Unsigned @OriginalName("__be16") short protocol;

    public @Unsigned @OriginalName("__be32") int key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_gre"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_gre extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_gre_filter val;

    public ib_flow_gre_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_mpls_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_mpls_filter extends Struct {
    public @Unsigned @OriginalName("__be32") int tag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_mpls"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_mpls extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;

    public ib_flow_mpls_filter val;

    public ib_flow_mpls_filter mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_action_tag"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_action_tag extends Struct {
    public ib_flow_spec_type type;

    public @Unsigned short size;

    public @Unsigned int tag_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_action_drop"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_action_drop extends Struct {
    public ib_flow_spec_type type;

    public @Unsigned short size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_action_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_action_handle extends Struct {
    public ib_flow_spec_type type;

    public @Unsigned short size;

    public Ptr<ib_flow_action> act;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_action"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_action extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;

    public ib_flow_action_type type;

    public atomic_t usecnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_spec_action_count"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec_action_count extends Struct {
    public ib_flow_spec_type type;

    public @Unsigned short size;

    public Ptr<ib_counters> counters;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_counters"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_counters extends Struct {
    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;

    public atomic_t usecnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union ib_flow_spec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_spec extends Union {
    public anon_member_of_ib_flow_spec anon0;

    public ib_flow_spec_eth eth;

    public ib_flow_spec_ib ib;

    public ib_flow_spec_ipv4 ipv4;

    public ib_flow_spec_tcp_udp tcp_udp;

    public ib_flow_spec_ipv6 ipv6;

    public ib_flow_spec_tunnel tunnel;

    public ib_flow_spec_esp esp;

    public ib_flow_spec_gre gre;

    public ib_flow_spec_mpls mpls;

    public ib_flow_spec_action_tag flow_tag;

    public ib_flow_spec_action_drop drop;

    public ib_flow_spec_action_handle action;

    public ib_flow_spec_action_count flow_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow_attr extends Struct {
    public ib_flow_attr_type type;

    public @Unsigned short size;

    public @Unsigned short priority;

    public @Unsigned int flags;

    public char num_of_specs;

    public @Unsigned int port;

    public ib_flow_spec @Size(0) [] flows;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_flow"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_flow extends Struct {
    public Ptr<ib_qp> qp;

    public Ptr<ib_device> device;

    public Ptr<ib_uobject> uobject;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ib_flow_action_type"
  )
  public enum ib_flow_action_type implements Enum<ib_flow_action_type>, TypedEnum<ib_flow_action_type, java.lang. @Unsigned Integer> {
    /**
     * {@code IB_FLOW_ACTION_UNSPECIFIED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "IB_FLOW_ACTION_UNSPECIFIED"
    )
    IB_FLOW_ACTION_UNSPECIFIED,

    /**
     * {@code IB_FLOW_ACTION_ESP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "IB_FLOW_ACTION_ESP"
    )
    IB_FLOW_ACTION_ESP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_cache"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_cache extends Struct {
    public @Unsigned long subnet_prefix;

    public @OriginalName("ib_pkey_cache") Ptr<?> pkey;

    public @OriginalName("ib_gid_table") Ptr<?> gid;

    public char lmc;

    public ib_port_state port_state;

    public ib_port_state last_port_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_immutable"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_immutable extends Struct {
    public int pkey_tbl_len;

    public int gid_tbl_len;

    public @Unsigned int core_cap_flags;

    public @Unsigned int max_mad_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_port_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_port_data extends Struct {
    public Ptr<ib_device> ib_dev;

    public ib_port_immutable immutable;

    public @OriginalName("spinlock_t") spinlock pkey_list_lock;

    public @OriginalName("spinlock_t") spinlock netdev_lock;

    public list_head pkey_list;

    public ib_port_cache cache;

    public Ptr<net_device> netdev;

    public @OriginalName("netdevice_tracker") lockdep_map_p netdev_tracker;

    public hlist_node ndev_hash_link;

    public rdma_port_counter port_counter;

    public @OriginalName("ib_port") Ptr<?> sysfs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_counters_read_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_counters_read_attr extends Struct {
    public Ptr<java.lang. @Unsigned Long> counters_buff;

    public @Unsigned int ncounters;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_device_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_device_ops extends Struct {
    public Ptr<module> owner;

    public rdma_driver_id driver_id;

    public @Unsigned int uverbs_abi_ver;

    public @Unsigned int uverbs_no_driver_id_binding;

    public Ptr<attribute_group> device_group;

    public Ptr<Ptr<attribute_group>> port_groups;

    public Ptr<?> post_send;

    public Ptr<?> post_recv;

    public Ptr<?> drain_rq;

    public Ptr<?> drain_sq;

    public Ptr<?> poll_cq;

    public Ptr<?> peek_cq;

    public Ptr<?> req_notify_cq;

    public Ptr<?> post_srq_recv;

    public Ptr<?> process_mad;

    public Ptr<?> query_device;

    public Ptr<?> modify_device;

    public Ptr<?> get_dev_fw_str;

    public Ptr<?> get_vector_affinity;

    public Ptr<?> query_port;

    public Ptr<?> modify_port;

    public Ptr<?> get_port_immutable;

    public Ptr<?> get_link_layer;

    public Ptr<?> get_netdev;

    public Ptr<?> alloc_rdma_netdev;

    public Ptr<?> rdma_netdev_get_params;

    public Ptr<?> query_gid;

    public Ptr<?> add_gid;

    public Ptr<?> del_gid;

    public Ptr<?> query_pkey;

    public Ptr<?> alloc_ucontext;

    public Ptr<?> dealloc_ucontext;

    public Ptr<?> mmap;

    public Ptr<?> mmap_free;

    public Ptr<?> disassociate_ucontext;

    public Ptr<?> alloc_pd;

    public Ptr<?> dealloc_pd;

    public Ptr<?> create_ah;

    public Ptr<?> create_user_ah;

    public Ptr<?> modify_ah;

    public Ptr<?> query_ah;

    public Ptr<?> destroy_ah;

    public Ptr<?> create_srq;

    public Ptr<?> modify_srq;

    public Ptr<?> query_srq;

    public Ptr<?> destroy_srq;

    public Ptr<?> create_qp;

    public Ptr<?> modify_qp;

    public Ptr<?> query_qp;

    public Ptr<?> destroy_qp;

    public Ptr<?> create_cq;

    public Ptr<?> create_cq_umem;

    public Ptr<?> modify_cq;

    public Ptr<?> destroy_cq;

    public Ptr<?> resize_cq;

    public Ptr<?> pre_destroy_cq;

    public Ptr<?> post_destroy_cq;

    public Ptr<?> get_dma_mr;

    public Ptr<?> reg_user_mr;

    public Ptr<?> reg_user_mr_dmabuf;

    public Ptr<?> rereg_user_mr;

    public Ptr<?> dereg_mr;

    public Ptr<?> alloc_mr;

    public Ptr<?> alloc_mr_integrity;

    public Ptr<?> advise_mr;

    public Ptr<?> map_mr_sg;

    public Ptr<?> check_mr_status;

    public Ptr<?> alloc_mw;

    public Ptr<?> dealloc_mw;

    public Ptr<?> attach_mcast;

    public Ptr<?> detach_mcast;

    public Ptr<?> alloc_xrcd;

    public Ptr<?> dealloc_xrcd;

    public Ptr<?> create_flow;

    public Ptr<?> destroy_flow;

    public Ptr<?> destroy_flow_action;

    public Ptr<?> set_vf_link_state;

    public Ptr<?> get_vf_config;

    public Ptr<?> get_vf_stats;

    public Ptr<?> get_vf_guid;

    public Ptr<?> set_vf_guid;

    public Ptr<?> create_wq;

    public Ptr<?> destroy_wq;

    public Ptr<?> modify_wq;

    public Ptr<?> create_rwq_ind_table;

    public Ptr<?> destroy_rwq_ind_table;

    public Ptr<?> alloc_dm;

    public Ptr<?> dealloc_dm;

    public Ptr<?> alloc_dmah;

    public Ptr<?> dealloc_dmah;

    public Ptr<?> reg_dm_mr;

    public Ptr<?> create_counters;

    public Ptr<?> destroy_counters;

    public Ptr<?> read_counters;

    public Ptr<?> map_mr_sg_pi;

    public Ptr<?> alloc_hw_device_stats;

    public Ptr<?> alloc_hw_port_stats;

    public Ptr<?> get_hw_stats;

    public Ptr<?> modify_hw_stat;

    public Ptr<?> fill_res_mr_entry;

    public Ptr<?> fill_res_mr_entry_raw;

    public Ptr<?> fill_res_cq_entry;

    public Ptr<?> fill_res_cq_entry_raw;

    public Ptr<?> fill_res_qp_entry;

    public Ptr<?> fill_res_qp_entry_raw;

    public Ptr<?> fill_res_cm_id_entry;

    public Ptr<?> fill_res_srq_entry;

    public Ptr<?> fill_res_srq_entry_raw;

    public Ptr<?> enable_driver;

    public Ptr<?> dealloc_driver;

    public Ptr<?> iw_add_ref;

    public Ptr<?> iw_rem_ref;

    public Ptr<?> iw_get_qp;

    public Ptr<?> iw_connect;

    public Ptr<?> iw_accept;

    public Ptr<?> iw_reject;

    public Ptr<?> iw_create_listen;

    public Ptr<?> iw_destroy_listen;

    public Ptr<?> counter_bind_qp;

    public Ptr<?> counter_unbind_qp;

    public Ptr<?> counter_dealloc;

    public Ptr<?> counter_alloc_stats;

    public Ptr<?> counter_update_stats;

    public Ptr<?> counter_init;

    public Ptr<?> fill_stat_mr_entry;

    public Ptr<?> query_ucontext;

    public Ptr<?> get_numa_node;

    public Ptr<?> add_sub_dev;

    public Ptr<?> del_sub_dev;

    public Ptr<?> ufile_hw_cleanup;

    public Ptr<?> report_port_event;

    public @Unsigned long size_ib_ah;

    public @Unsigned long size_ib_counters;

    public @Unsigned long size_ib_cq;

    public @Unsigned long size_ib_dmah;

    public @Unsigned long size_ib_mw;

    public @Unsigned long size_ib_pd;

    public @Unsigned long size_ib_qp;

    public @Unsigned long size_ib_rwq_ind_table;

    public @Unsigned long size_ib_srq;

    public @Unsigned long size_ib_ucontext;

    public @Unsigned long size_ib_xrcd;

    public @Unsigned long size_rdma_counter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ib_core_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ib_core_device extends Struct {
    public device dev;

    public possible_net_t rdma_net;

    public Ptr<kobject> ports_kobj;

    public list_head port_list;

    public Ptr<ib_device> owner;
  }
}
