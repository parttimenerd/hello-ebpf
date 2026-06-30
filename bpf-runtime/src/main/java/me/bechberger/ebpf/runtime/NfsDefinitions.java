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
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
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
 * Generated class for BPF runtime types that start with nfs
 */
@java.lang.SuppressWarnings("unused")
public final class NfsDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int nfs_localio_errno_to_nfs4_stat(int errno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("nfs_ssc_register((const struct nfs_ssc_client_ops *)$arg1)")
  public static void nfs_ssc_register(Ptr<nfs_ssc_client_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("nfs_ssc_unregister((const struct nfs_ssc_client_ops *)$arg1)")
  public static void nfs_ssc_unregister(Ptr<nfs_ssc_client_ops> ops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int nfs_stat_to_errno(nfs_stat status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_lock_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_lock_info extends Struct {
    public @Unsigned int state;

    public @OriginalName("nlm_lockowner") Ptr<?> owner;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_fh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_fh extends Struct {
    public @Unsigned short size;

    public char @Size(128) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum nfs_opnum4"
  )
  public enum nfs_opnum4 implements Enum<nfs_opnum4>, TypedEnum<nfs_opnum4, java.lang. @Unsigned Integer> {
    /**
     * {@code OP_ACCESS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "OP_ACCESS"
    )
    OP_ACCESS,

    /**
     * {@code OP_CLOSE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "OP_CLOSE"
    )
    OP_CLOSE,

    /**
     * {@code OP_COMMIT = 5}
     */
    @EnumMember(
        value = 5L,
        name = "OP_COMMIT"
    )
    OP_COMMIT,

    /**
     * {@code OP_CREATE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "OP_CREATE"
    )
    OP_CREATE,

    /**
     * {@code OP_DELEGPURGE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "OP_DELEGPURGE"
    )
    OP_DELEGPURGE,

    /**
     * {@code OP_DELEGRETURN = 8}
     */
    @EnumMember(
        value = 8L,
        name = "OP_DELEGRETURN"
    )
    OP_DELEGRETURN,

    /**
     * {@code OP_GETATTR = 9}
     */
    @EnumMember(
        value = 9L,
        name = "OP_GETATTR"
    )
    OP_GETATTR,

    /**
     * {@code OP_GETFH = 10}
     */
    @EnumMember(
        value = 10L,
        name = "OP_GETFH"
    )
    OP_GETFH,

    /**
     * {@code OP_LINK = 11}
     */
    @EnumMember(
        value = 11L,
        name = "OP_LINK"
    )
    OP_LINK,

    /**
     * {@code OP_LOCK = 12}
     */
    @EnumMember(
        value = 12L,
        name = "OP_LOCK"
    )
    OP_LOCK,

    /**
     * {@code OP_LOCKT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "OP_LOCKT"
    )
    OP_LOCKT,

    /**
     * {@code OP_LOCKU = 14}
     */
    @EnumMember(
        value = 14L,
        name = "OP_LOCKU"
    )
    OP_LOCKU,

    /**
     * {@code OP_LOOKUP = 15}
     */
    @EnumMember(
        value = 15L,
        name = "OP_LOOKUP"
    )
    OP_LOOKUP,

    /**
     * {@code OP_LOOKUPP = 16}
     */
    @EnumMember(
        value = 16L,
        name = "OP_LOOKUPP"
    )
    OP_LOOKUPP,

    /**
     * {@code OP_NVERIFY = 17}
     */
    @EnumMember(
        value = 17L,
        name = "OP_NVERIFY"
    )
    OP_NVERIFY,

    /**
     * {@code OP_OPEN = 18}
     */
    @EnumMember(
        value = 18L,
        name = "OP_OPEN"
    )
    OP_OPEN,

    /**
     * {@code OP_OPENATTR = 19}
     */
    @EnumMember(
        value = 19L,
        name = "OP_OPENATTR"
    )
    OP_OPENATTR,

    /**
     * {@code OP_OPEN_CONFIRM = 20}
     */
    @EnumMember(
        value = 20L,
        name = "OP_OPEN_CONFIRM"
    )
    OP_OPEN_CONFIRM,

    /**
     * {@code OP_OPEN_DOWNGRADE = 21}
     */
    @EnumMember(
        value = 21L,
        name = "OP_OPEN_DOWNGRADE"
    )
    OP_OPEN_DOWNGRADE,

    /**
     * {@code OP_PUTFH = 22}
     */
    @EnumMember(
        value = 22L,
        name = "OP_PUTFH"
    )
    OP_PUTFH,

    /**
     * {@code OP_PUTPUBFH = 23}
     */
    @EnumMember(
        value = 23L,
        name = "OP_PUTPUBFH"
    )
    OP_PUTPUBFH,

    /**
     * {@code OP_PUTROOTFH = 24}
     */
    @EnumMember(
        value = 24L,
        name = "OP_PUTROOTFH"
    )
    OP_PUTROOTFH,

    /**
     * {@code OP_READ = 25}
     */
    @EnumMember(
        value = 25L,
        name = "OP_READ"
    )
    OP_READ,

    /**
     * {@code OP_READDIR = 26}
     */
    @EnumMember(
        value = 26L,
        name = "OP_READDIR"
    )
    OP_READDIR,

    /**
     * {@code OP_READLINK = 27}
     */
    @EnumMember(
        value = 27L,
        name = "OP_READLINK"
    )
    OP_READLINK,

    /**
     * {@code OP_REMOVE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "OP_REMOVE"
    )
    OP_REMOVE,

    /**
     * {@code OP_RENAME = 29}
     */
    @EnumMember(
        value = 29L,
        name = "OP_RENAME"
    )
    OP_RENAME,

    /**
     * {@code OP_RENEW = 30}
     */
    @EnumMember(
        value = 30L,
        name = "OP_RENEW"
    )
    OP_RENEW,

    /**
     * {@code OP_RESTOREFH = 31}
     */
    @EnumMember(
        value = 31L,
        name = "OP_RESTOREFH"
    )
    OP_RESTOREFH,

    /**
     * {@code OP_SAVEFH = 32}
     */
    @EnumMember(
        value = 32L,
        name = "OP_SAVEFH"
    )
    OP_SAVEFH,

    /**
     * {@code OP_SECINFO = 33}
     */
    @EnumMember(
        value = 33L,
        name = "OP_SECINFO"
    )
    OP_SECINFO,

    /**
     * {@code OP_SETATTR = 34}
     */
    @EnumMember(
        value = 34L,
        name = "OP_SETATTR"
    )
    OP_SETATTR,

    /**
     * {@code OP_SETCLIENTID = 35}
     */
    @EnumMember(
        value = 35L,
        name = "OP_SETCLIENTID"
    )
    OP_SETCLIENTID,

    /**
     * {@code OP_SETCLIENTID_CONFIRM = 36}
     */
    @EnumMember(
        value = 36L,
        name = "OP_SETCLIENTID_CONFIRM"
    )
    OP_SETCLIENTID_CONFIRM,

    /**
     * {@code OP_VERIFY = 37}
     */
    @EnumMember(
        value = 37L,
        name = "OP_VERIFY"
    )
    OP_VERIFY,

    /**
     * {@code OP_WRITE = 38}
     */
    @EnumMember(
        value = 38L,
        name = "OP_WRITE"
    )
    OP_WRITE,

    /**
     * {@code OP_RELEASE_LOCKOWNER = 39}
     */
    @EnumMember(
        value = 39L,
        name = "OP_RELEASE_LOCKOWNER"
    )
    OP_RELEASE_LOCKOWNER,

    /**
     * {@code OP_BACKCHANNEL_CTL = 40}
     */
    @EnumMember(
        value = 40L,
        name = "OP_BACKCHANNEL_CTL"
    )
    OP_BACKCHANNEL_CTL,

    /**
     * {@code OP_BIND_CONN_TO_SESSION = 41}
     */
    @EnumMember(
        value = 41L,
        name = "OP_BIND_CONN_TO_SESSION"
    )
    OP_BIND_CONN_TO_SESSION,

    /**
     * {@code OP_EXCHANGE_ID = 42}
     */
    @EnumMember(
        value = 42L,
        name = "OP_EXCHANGE_ID"
    )
    OP_EXCHANGE_ID,

    /**
     * {@code OP_CREATE_SESSION = 43}
     */
    @EnumMember(
        value = 43L,
        name = "OP_CREATE_SESSION"
    )
    OP_CREATE_SESSION,

    /**
     * {@code OP_DESTROY_SESSION = 44}
     */
    @EnumMember(
        value = 44L,
        name = "OP_DESTROY_SESSION"
    )
    OP_DESTROY_SESSION,

    /**
     * {@code OP_FREE_STATEID = 45}
     */
    @EnumMember(
        value = 45L,
        name = "OP_FREE_STATEID"
    )
    OP_FREE_STATEID,

    /**
     * {@code OP_GET_DIR_DELEGATION = 46}
     */
    @EnumMember(
        value = 46L,
        name = "OP_GET_DIR_DELEGATION"
    )
    OP_GET_DIR_DELEGATION,

    /**
     * {@code OP_GETDEVICEINFO = 47}
     */
    @EnumMember(
        value = 47L,
        name = "OP_GETDEVICEINFO"
    )
    OP_GETDEVICEINFO,

    /**
     * {@code OP_GETDEVICELIST = 48}
     */
    @EnumMember(
        value = 48L,
        name = "OP_GETDEVICELIST"
    )
    OP_GETDEVICELIST,

    /**
     * {@code OP_LAYOUTCOMMIT = 49}
     */
    @EnumMember(
        value = 49L,
        name = "OP_LAYOUTCOMMIT"
    )
    OP_LAYOUTCOMMIT,

    /**
     * {@code OP_LAYOUTGET = 50}
     */
    @EnumMember(
        value = 50L,
        name = "OP_LAYOUTGET"
    )
    OP_LAYOUTGET,

    /**
     * {@code OP_LAYOUTRETURN = 51}
     */
    @EnumMember(
        value = 51L,
        name = "OP_LAYOUTRETURN"
    )
    OP_LAYOUTRETURN,

    /**
     * {@code OP_SECINFO_NO_NAME = 52}
     */
    @EnumMember(
        value = 52L,
        name = "OP_SECINFO_NO_NAME"
    )
    OP_SECINFO_NO_NAME,

    /**
     * {@code OP_SEQUENCE = 53}
     */
    @EnumMember(
        value = 53L,
        name = "OP_SEQUENCE"
    )
    OP_SEQUENCE,

    /**
     * {@code OP_SET_SSV = 54}
     */
    @EnumMember(
        value = 54L,
        name = "OP_SET_SSV"
    )
    OP_SET_SSV,

    /**
     * {@code OP_TEST_STATEID = 55}
     */
    @EnumMember(
        value = 55L,
        name = "OP_TEST_STATEID"
    )
    OP_TEST_STATEID,

    /**
     * {@code OP_WANT_DELEGATION = 56}
     */
    @EnumMember(
        value = 56L,
        name = "OP_WANT_DELEGATION"
    )
    OP_WANT_DELEGATION,

    /**
     * {@code OP_DESTROY_CLIENTID = 57}
     */
    @EnumMember(
        value = 57L,
        name = "OP_DESTROY_CLIENTID"
    )
    OP_DESTROY_CLIENTID,

    /**
     * {@code OP_RECLAIM_COMPLETE = 58}
     */
    @EnumMember(
        value = 58L,
        name = "OP_RECLAIM_COMPLETE"
    )
    OP_RECLAIM_COMPLETE,

    /**
     * {@code OP_ALLOCATE = 59}
     */
    @EnumMember(
        value = 59L,
        name = "OP_ALLOCATE"
    )
    OP_ALLOCATE,

    /**
     * {@code OP_COPY = 60}
     */
    @EnumMember(
        value = 60L,
        name = "OP_COPY"
    )
    OP_COPY,

    /**
     * {@code OP_COPY_NOTIFY = 61}
     */
    @EnumMember(
        value = 61L,
        name = "OP_COPY_NOTIFY"
    )
    OP_COPY_NOTIFY,

    /**
     * {@code OP_DEALLOCATE = 62}
     */
    @EnumMember(
        value = 62L,
        name = "OP_DEALLOCATE"
    )
    OP_DEALLOCATE,

    /**
     * {@code OP_IO_ADVISE = 63}
     */
    @EnumMember(
        value = 63L,
        name = "OP_IO_ADVISE"
    )
    OP_IO_ADVISE,

    /**
     * {@code OP_LAYOUTERROR = 64}
     */
    @EnumMember(
        value = 64L,
        name = "OP_LAYOUTERROR"
    )
    OP_LAYOUTERROR,

    /**
     * {@code OP_LAYOUTSTATS = 65}
     */
    @EnumMember(
        value = 65L,
        name = "OP_LAYOUTSTATS"
    )
    OP_LAYOUTSTATS,

    /**
     * {@code OP_OFFLOAD_CANCEL = 66}
     */
    @EnumMember(
        value = 66L,
        name = "OP_OFFLOAD_CANCEL"
    )
    OP_OFFLOAD_CANCEL,

    /**
     * {@code OP_OFFLOAD_STATUS = 67}
     */
    @EnumMember(
        value = 67L,
        name = "OP_OFFLOAD_STATUS"
    )
    OP_OFFLOAD_STATUS,

    /**
     * {@code OP_READ_PLUS = 68}
     */
    @EnumMember(
        value = 68L,
        name = "OP_READ_PLUS"
    )
    OP_READ_PLUS,

    /**
     * {@code OP_SEEK = 69}
     */
    @EnumMember(
        value = 69L,
        name = "OP_SEEK"
    )
    OP_SEEK,

    /**
     * {@code OP_WRITE_SAME = 70}
     */
    @EnumMember(
        value = 70L,
        name = "OP_WRITE_SAME"
    )
    OP_WRITE_SAME,

    /**
     * {@code OP_CLONE = 71}
     */
    @EnumMember(
        value = 71L,
        name = "OP_CLONE"
    )
    OP_CLONE,

    /**
     * {@code OP_GETXATTR = 72}
     */
    @EnumMember(
        value = 72L,
        name = "OP_GETXATTR"
    )
    OP_GETXATTR,

    /**
     * {@code OP_SETXATTR = 73}
     */
    @EnumMember(
        value = 73L,
        name = "OP_SETXATTR"
    )
    OP_SETXATTR,

    /**
     * {@code OP_LISTXATTRS = 74}
     */
    @EnumMember(
        value = 74L,
        name = "OP_LISTXATTRS"
    )
    OP_LISTXATTRS,

    /**
     * {@code OP_REMOVEXATTR = 75}
     */
    @EnumMember(
        value = 75L,
        name = "OP_REMOVEXATTR"
    )
    OP_REMOVEXATTR,

    /**
     * {@code OP_ILLEGAL = 10044}
     */
    @EnumMember(
        value = 10044L,
        name = "OP_ILLEGAL"
    )
    OP_ILLEGAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_fsid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_fsid extends Struct {
    public @Unsigned @OriginalName("uint64_t") long major;

    public @Unsigned @OriginalName("uint64_t") long minor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_fattr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_fattr extends Struct {
    public @Unsigned long valid;

    public @Unsigned @OriginalName("umode_t") short mode;

    public @Unsigned int nlink;

    public kuid_t uid;

    public kgid_t gid;

    public @Unsigned @OriginalName("dev_t") int rdev;

    public @Unsigned long size;

    public du_of_nfs_fattr du;

    public nfs_fsid fsid;

    public @Unsigned long fileid;

    public @Unsigned long mounted_on_fileid;

    public timespec64 atime;

    public timespec64 mtime;

    public timespec64 ctime;

    public timespec64 btime;

    public @Unsigned long change_attr;

    public @Unsigned long pre_change_attr;

    public @Unsigned long pre_size;

    public timespec64 pre_mtime;

    public timespec64 pre_ctime;

    public @Unsigned long time_start;

    public @Unsigned long gencount;

    public Ptr<nfs4_string> owner_name;

    public Ptr<nfs4_string> group_name;

    public Ptr<nfs4_threshold> mdsthreshold;

    public Ptr<nfs4_label> label;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_fsinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_fsinfo extends Struct {
    public Ptr<nfs_fattr> fattr;

    public @Unsigned int rtmax;

    public @Unsigned int rtpref;

    public @Unsigned int rtmult;

    public @Unsigned int wtmax;

    public @Unsigned int wtpref;

    public @Unsigned int wtmult;

    public @Unsigned int dtpref;

    public @Unsigned long maxfilesize;

    public timespec64 time_delta;

    public @Unsigned int lease_time;

    public @Unsigned int nlayouttypes;

    public @Unsigned int @Size(8) [] layouttype;

    public @Unsigned int blksize;

    public @Unsigned int clone_blksize;

    public nfs4_change_attr_type change_attr_type;

    public @Unsigned int xattr_support;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_fsstat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_fsstat extends Struct {
    public Ptr<nfs_fattr> fattr;

    public @Unsigned long tbytes;

    public @Unsigned long fbytes;

    public @Unsigned long abytes;

    public @Unsigned long tfiles;

    public @Unsigned long ffiles;

    public @Unsigned long afiles;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_pathconf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_pathconf extends Struct {
    public Ptr<nfs_fattr> fattr;

    public @Unsigned int max_link;

    public @Unsigned int max_namelen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_open_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_open_context extends Struct {
    public nfs_lock_context lock_context;

    public @OriginalName("fl_owner_t") Ptr<?> flock_owner;

    public Ptr<dentry> dentry;

    public Ptr<cred> cred;

    public Ptr<rpc_cred> ll_cred;

    public Ptr<nfs4_state> state;

    public @Unsigned @OriginalName("fmode_t") int mode;

    public int error;

    public @Unsigned long flags;

    public Ptr<nfs4_threshold> mdsthreshold;

    public list_head list;

    public callback_head callback_head;

    public nfs_file_localio nfl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_server"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_server extends Struct {
    public Ptr<nfs_client> nfs_client;

    public list_head client_link;

    public list_head master_link;

    public Ptr<rpc_clnt> client;

    public Ptr<rpc_clnt> client_acl;

    public @OriginalName("nlm_host") Ptr<?> nlm_host;

    public @OriginalName("nfs_iostats") Ptr<?> io_stats;

    public @OriginalName("wait_queue_head_t") wait_queue_head write_congestion_wait;

    public @OriginalName("atomic_long_t") atomic64_t writeback;

    public @Unsigned int write_congested;

    public @Unsigned int flags;

    public @Unsigned int automount_inherit;

    public @Unsigned int caps;

    public @Unsigned long fattr_valid;

    public @Unsigned int rsize;

    public @Unsigned int rpages;

    public @Unsigned int wsize;

    public @Unsigned int wtmult;

    public @Unsigned int dtsize;

    public @Unsigned short port;

    public @Unsigned int bsize;

    public @Unsigned int gxasize;

    public @Unsigned int sxasize;

    public @Unsigned int lxasize;

    public @Unsigned int acregmin;

    public @Unsigned int acregmax;

    public @Unsigned int acdirmin;

    public @Unsigned int acdirmax;

    public @Unsigned int namelen;

    public @Unsigned int options;

    public @Unsigned int clone_blksize;

    public nfs4_change_attr_type change_attr_type;

    public nfs_fsid fsid;

    public int s_sysfs_id;

    public @Unsigned long maxfilesize;

    public @Unsigned long mount_time;

    public Ptr<super_block> _super;

    public @Unsigned @OriginalName("dev_t") int s_dev;

    public nfs_auth_info auth_info;

    public @OriginalName("fscache_volume") Ptr<?> fscache;

    public String fscache_uniq;

    public @Unsigned int fh_expire_type;

    public @Unsigned int pnfs_blksize;

    public @Unsigned int @Size(3) [] attr_bitmask;

    public @Unsigned int @Size(3) [] attr_bitmask_nl;

    public @Unsigned int @Size(3) [] exclcreat_bitmask;

    public @Unsigned int @Size(3) [] cache_consistency_bitmask;

    public @Unsigned int acl_bitmask;

    public @OriginalName("pnfs_layoutdriver_type") Ptr<?> pnfs_curr_ld;

    public rpc_wait_queue roc_rpcwaitq;

    public rb_root state_owners;

    public atomic64_t owner_ctr;

    public list_head state_owners_lru;

    public list_head layouts;

    public list_head delegations;

    public @OriginalName("atomic_long_t") atomic64_t nr_active_delegations;

    public @Unsigned int delegation_hash_mask;

    public Ptr<hlist_head> delegation_hash_table;

    public list_head ss_copies;

    public list_head ss_src_copies;

    public @Unsigned long delegation_flags;

    public @Unsigned long delegation_gen;

    public @Unsigned long mig_gen;

    public @Unsigned long mig_status;

    public Ptr<?> destroy;

    public atomic_t active;

    public __kernel_sockaddr_storage mountd_address;

    public @Unsigned long mountd_addrlen;

    public @Unsigned int mountd_version;

    public @Unsigned short mountd_port;

    public @Unsigned short mountd_protocol;

    public rpc_wait_queue uoc_rpcwaitq;

    public @Unsigned int read_hdrsize;

    public Ptr<cred> cred;

    public boolean has_sec_mnt_opts;

    public kobject kobj;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_client"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_client extends Struct {
    public @OriginalName("refcount_t") refcount_struct cl_count;

    public atomic_t cl_mds_count;

    public int cl_cons_state;

    public @Unsigned long cl_res_state;

    public @Unsigned long cl_flags;

    public __kernel_sockaddr_storage cl_addr;

    public @Unsigned long cl_addrlen;

    public String cl_hostname;

    public String cl_acceptor;

    public list_head cl_share_link;

    public list_head cl_superblocks;

    public Ptr<rpc_clnt> cl_rpcclient;

    public Ptr<nfs_rpc_ops> rpc_ops;

    public int cl_proto;

    public @OriginalName("nfs_subversion") Ptr<?> cl_nfs_mod;

    public @Unsigned int cl_minorversion;

    public @Unsigned int cl_nconnect;

    public @Unsigned int cl_max_connect;

    public String cl_principal;

    public xprtsec_parms cl_xprtsec;

    public list_head cl_ds_clients;

    public @Unsigned long cl_clientid;

    public nfs4_verifier cl_confirm;

    public @Unsigned long cl_state;

    public @OriginalName("spinlock_t") spinlock cl_lock;

    public @Unsigned long cl_lease_time;

    public @Unsigned long cl_last_renewal;

    public delayed_work cl_renewd;

    public rpc_wait_queue cl_rpcwaitq;

    public @OriginalName("idmap") Ptr<?> cl_idmap;

    public String cl_owner_id;

    public @Unsigned int cl_cb_ident;

    public Ptr<nfs4_minor_version_ops> cl_mvops;

    public @Unsigned long cl_mig_gen;

    public @OriginalName("nfs4_slot_table") Ptr<?> cl_slot_tbl;

    public @Unsigned int cl_seqid;

    public @Unsigned int cl_exchange_flags;

    public @OriginalName("nfs4_session") Ptr<?> cl_session;

    public boolean cl_preserve_clid;

    public Ptr<nfs41_server_owner> cl_serverowner;

    public Ptr<nfs41_server_scope> cl_serverscope;

    public Ptr<nfs41_impl_id> cl_implid;

    public @Unsigned long cl_sp4_flags;

    public @OriginalName("wait_queue_head_t") wait_queue_head cl_lock_waitq;

    public char @Size(48) [] cl_ipaddr;

    public Ptr<net> cl_net;

    public @OriginalName("netns_tracker") lockdep_map_p cl_ns_tracker;

    public list_head pending_cb_stateids;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_seqid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_seqid extends Struct {
    public Ptr<nfs_seqid_counter> sequence;

    public list_head list;

    public Ptr<rpc_task> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_write_verifier"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_write_verifier extends Struct {
    public char @Size(8) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_writeverf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_writeverf extends Struct {
    public nfs_write_verifier verifier;

    public nfs3_stable_how committed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_pgio_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_pgio_args extends Struct {
    public nfs4_sequence_args seq_args;

    public Ptr<nfs_fh> fh;

    public Ptr<nfs_open_context> context;

    public Ptr<nfs_lock_context> lock_context;

    public nfs4_stateid_struct stateid;

    public @Unsigned long offset;

    public @Unsigned int count;

    public @Unsigned int pgbase;

    public Ptr<Ptr<page>> pages;

    @InlineUnion(23293)
    public @Unsigned int replen;

    @InlineUnion(23293)
    public anon_member_of_anon_member_of_nfs_pgio_args anon9$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_lock_context"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_lock_context extends Struct {
    public @OriginalName("refcount_t") refcount_struct count;

    public list_head list;

    public Ptr<nfs_open_context> open_context;

    public @OriginalName("fl_owner_t") Ptr<?> lockowner;

    public atomic_t io_count;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_pgio_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_pgio_res extends Struct {
    public nfs4_sequence_res seq_res;

    public Ptr<nfs_fattr> fattr;

    public @Unsigned long count;

    public @Unsigned int op_status;

    @InlineUnion(23300)
    public anon_member_of_anon_member_of_nfs_pgio_res anon4$0;

    @InlineUnion(23300)
    public anon_member_of_anon_member_of_nfs_pgio_res anon4$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_commitargs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_commitargs extends Struct {
    public nfs4_sequence_args seq_args;

    public Ptr<nfs_fh> fh;

    public @Unsigned long offset;

    public @Unsigned int count;

    public Ptr<java.lang. @Unsigned Integer> bitmask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_commitres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_commitres extends Struct {
    public nfs4_sequence_res seq_res;

    public @Unsigned int op_status;

    public Ptr<nfs_fattr> fattr;

    public Ptr<nfs_writeverf> verf;

    public Ptr<nfs_server> server;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_removeargs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_removeargs extends Struct {
    public nfs4_sequence_args seq_args;

    public Ptr<nfs_fh> fh;

    public qstr name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_removeres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_removeres extends Struct {
    public nfs4_sequence_res seq_res;

    public Ptr<nfs_server> server;

    public Ptr<nfs_fattr> dir_attr;

    public nfs4_change_info cinfo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_renameargs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_renameargs extends Struct {
    public nfs4_sequence_args seq_args;

    public Ptr<nfs_fh> old_dir;

    public Ptr<nfs_fh> new_dir;

    public Ptr<qstr> old_name;

    public Ptr<qstr> new_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_renameres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_renameres extends Struct {
    public nfs4_sequence_res seq_res;

    public Ptr<nfs_server> server;

    public nfs4_change_info old_cinfo;

    public Ptr<nfs_fattr> old_fattr;

    public nfs4_change_info new_cinfo;

    public Ptr<nfs_fattr> new_fattr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_auth_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_auth_info extends Struct {
    public @Unsigned int flavor_len;

    public @Unsigned @OriginalName("rpc_authflavor_t") int @Size(12) [] flavors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_entry extends Struct {
    public @Unsigned long ino;

    public @Unsigned long cookie;

    public String name;

    public @Unsigned int len;

    public int eof;

    public Ptr<nfs_fh> fh;

    public Ptr<nfs_fattr> fattr;

    public char d_type;

    public Ptr<nfs_server> server;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_readdir_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_readdir_arg extends Struct {
    public Ptr<dentry> dentry;

    public Ptr<cred> cred;

    public Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> verf;

    public @Unsigned long cookie;

    public Ptr<Ptr<page>> pages;

    public @Unsigned int page_len;

    public boolean plus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_readdir_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_readdir_res extends Struct {
    public Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> verf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_page_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_page_array extends Struct {
    public Ptr<Ptr<page>> pagevec;

    public @Unsigned int npages;

    public Ptr<page> @Size(8) [] page_array;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_pgio_header"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_pgio_header extends Struct {
    public Ptr<inode> inode;

    public Ptr<cred> cred;

    public list_head pages;

    public @OriginalName("nfs_page") Ptr<?> req;

    public nfs_writeverf verf;

    public @Unsigned @OriginalName("fmode_t") int rw_mode;

    public @OriginalName("pnfs_layout_segment") Ptr<?> lseg;

    public @OriginalName("loff_t") long io_start;

    public Ptr<rpc_call_ops> mds_ops;

    public Ptr<?> release;

    public Ptr<nfs_pgio_completion_ops> completion_ops;

    public @OriginalName("nfs_rw_ops") Ptr<?> rw_ops;

    public @OriginalName("nfs_io_completion") Ptr<?> io_completion;

    public @OriginalName("nfs_direct_req") Ptr<?> dreq;

    public Ptr<?> netfs;

    public @Unsigned short retrans;

    public int pnfs_error;

    public int error;

    public @Unsigned int good_bytes;

    public @Unsigned long flags;

    public rpc_task task;

    public nfs_fattr fattr;

    public nfs_pgio_args args;

    public nfs_pgio_res res;

    public @Unsigned long timestamp;

    public Ptr<?> pgio_done_cb;

    public @Unsigned long mds_offset;

    public nfs_page_array page_array;

    public Ptr<nfs_client> ds_clp;

    public @Unsigned int ds_commit_idx;

    public @Unsigned int pgio_mirror_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_pgio_completion_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_pgio_completion_ops extends Struct {
    public Ptr<?> error_cleanup;

    public Ptr<?> init_hdr;

    public Ptr<?> completion;

    public Ptr<?> reschedule_io;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_mds_commit_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_mds_commit_info extends Struct {
    public atomic_t rpcs_out;

    public @OriginalName("atomic_long_t") atomic64_t ncommit;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_commit_completion_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_commit_completion_ops extends Struct {
    public Ptr<?> completion;

    public Ptr<?> resched_write;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_commit_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_commit_data extends Struct {
    public rpc_task task;

    public Ptr<inode> inode;

    public Ptr<cred> cred;

    public nfs_fattr fattr;

    public nfs_writeverf verf;

    public list_head pages;

    public list_head list;

    public @OriginalName("nfs_direct_req") Ptr<?> dreq;

    public nfs_commitargs args;

    public nfs_commitres res;

    public Ptr<nfs_open_context> context;

    public @OriginalName("pnfs_layout_segment") Ptr<?> lseg;

    public Ptr<nfs_client> ds_clp;

    public int ds_commit_index;

    public @OriginalName("loff_t") long lwb;

    public Ptr<rpc_call_ops> mds_ops;

    public Ptr<nfs_commit_completion_ops> completion_ops;

    public Ptr<?> commit_done_cb;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_commit_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_commit_info extends Struct {
    public Ptr<inode> inode;

    public Ptr<nfs_mds_commit_info> mds;

    public Ptr<pnfs_ds_commit_info> ds;

    public @OriginalName("nfs_direct_req") Ptr<?> dreq;

    public Ptr<nfs_commit_completion_ops> completion_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_unlinkdata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_unlinkdata extends Struct {
    public nfs_removeargs args;

    public nfs_removeres res;

    public Ptr<dentry> dentry;

    public @OriginalName("wait_queue_head_t") wait_queue_head wq;

    public Ptr<cred> cred;

    public nfs_fattr dir_attr;

    public long timeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_renamedata"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_renamedata extends Struct {
    public nfs_renameargs args;

    public nfs_renameres res;

    public rpc_task task;

    public Ptr<cred> cred;

    public Ptr<inode> old_dir;

    public Ptr<dentry> old_dentry;

    public nfs_fattr old_fattr;

    public Ptr<inode> new_dir;

    public Ptr<dentry> new_dentry;

    public nfs_fattr new_fattr;

    public Ptr<?> complete;

    public long timeout;

    public boolean cancelled;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_rpc_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_rpc_ops extends Struct {
    public @Unsigned int version;

    public Ptr<dentry_operations> dentry_ops;

    public Ptr<inode_operations> dir_inode_ops;

    public Ptr<inode_operations> file_inode_ops;

    public Ptr<file_operations> file_ops;

    public @OriginalName("nlmclnt_operations") Ptr<?> nlmclnt_ops;

    public Ptr<?> getroot;

    public Ptr<?> submount;

    public Ptr<?> try_get_tree;

    public Ptr<?> getattr;

    public Ptr<?> setattr;

    public Ptr<?> lookup;

    public Ptr<?> lookupp;

    public Ptr<?> access;

    public Ptr<?> readlink;

    public Ptr<?> create;

    public Ptr<?> remove;

    public Ptr<?> unlink_setup;

    public Ptr<?> unlink_rpc_prepare;

    public Ptr<?> unlink_done;

    public Ptr<?> rename_setup;

    public Ptr<?> rename_rpc_prepare;

    public Ptr<?> rename_done;

    public Ptr<?> link;

    public Ptr<?> symlink;

    public Ptr<?> mkdir;

    public Ptr<?> rmdir;

    public Ptr<?> readdir;

    public Ptr<?> mknod;

    public Ptr<?> statfs;

    public Ptr<?> fsinfo;

    public Ptr<?> pathconf;

    public Ptr<?> set_capabilities;

    public Ptr<?> decode_dirent;

    public Ptr<?> pgio_rpc_prepare;

    public Ptr<?> read_setup;

    public Ptr<?> read_done;

    public Ptr<?> write_setup;

    public Ptr<?> write_done;

    public Ptr<?> commit_setup;

    public Ptr<?> commit_rpc_prepare;

    public Ptr<?> commit_done;

    public Ptr<?> lock;

    public Ptr<?> lock_check_bounds;

    public Ptr<?> clear_acl_cache;

    public Ptr<?> close_context;

    public Ptr<?> open_context;

    public Ptr<?> have_delegation;

    public Ptr<?> return_delegation;

    public Ptr<?> alloc_client;

    public Ptr<?> init_client;

    public Ptr<?> free_client;

    public Ptr<?> create_server;

    public Ptr<?> clone_server;

    public Ptr<?> discover_trunking;

    public Ptr<?> enable_swap;

    public Ptr<?> disable_swap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_access_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_access_entry extends Struct {
    public rb_node rb_node;

    public list_head lru;

    public kuid_t fsuid;

    public kgid_t fsgid;

    public Ptr<group_info> group_info;

    public @Unsigned long timestamp;

    public @Unsigned int mask;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_file_localio"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_file_localio extends Struct {
    public @OriginalName("nfsd_file") Ptr<?> ro_file;

    public @OriginalName("nfsd_file") Ptr<?> rw_file;

    public list_head list;

    public Ptr<?> nfs_uuid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_ssc_client_ops_tbl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_ssc_client_ops_tbl extends Struct {
    public Ptr<nfs4_ssc_client_ops> ssc_nfs4_ops;

    public Ptr<nfs_ssc_client_ops> ssc_nfs_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_ssc_client_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_ssc_client_ops extends Struct {
    public Ptr<?> sco_sb_deactive;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct nfs_seqid_counter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class nfs_seqid_counter extends Struct {
    public @OriginalName("ktime_t") long create_time;

    public @Unsigned long owner_id;

    public int flags;

    public @Unsigned int counter;

    public @OriginalName("spinlock_t") spinlock lock;

    public list_head list;

    public rpc_wait_queue wait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum nfs_stat"
  )
  public enum nfs_stat implements Enum<nfs_stat>, TypedEnum<nfs_stat, java.lang. @Unsigned Integer> {
    /**
     * {@code NFS_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "NFS_OK"
    )
    NFS_OK,

    /**
     * {@code NFSERR_PERM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "NFSERR_PERM"
    )
    NFSERR_PERM,

    /**
     * {@code NFSERR_NOENT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "NFSERR_NOENT"
    )
    NFSERR_NOENT,

    /**
     * {@code NFSERR_IO = 5}
     */
    @EnumMember(
        value = 5L,
        name = "NFSERR_IO"
    )
    NFSERR_IO,

    /**
     * {@code NFSERR_NXIO = 6}
     */
    @EnumMember(
        value = 6L,
        name = "NFSERR_NXIO"
    )
    NFSERR_NXIO,

    /**
     * {@code NFSERR_EAGAIN = 11}
     */
    @EnumMember(
        value = 11L,
        name = "NFSERR_EAGAIN"
    )
    NFSERR_EAGAIN,

    /**
     * {@code NFSERR_ACCES = 13}
     */
    @EnumMember(
        value = 13L,
        name = "NFSERR_ACCES"
    )
    NFSERR_ACCES,

    /**
     * {@code NFSERR_EXIST = 17}
     */
    @EnumMember(
        value = 17L,
        name = "NFSERR_EXIST"
    )
    NFSERR_EXIST,

    /**
     * {@code NFSERR_XDEV = 18}
     */
    @EnumMember(
        value = 18L,
        name = "NFSERR_XDEV"
    )
    NFSERR_XDEV,

    /**
     * {@code NFSERR_NODEV = 19}
     */
    @EnumMember(
        value = 19L,
        name = "NFSERR_NODEV"
    )
    NFSERR_NODEV,

    /**
     * {@code NFSERR_NOTDIR = 20}
     */
    @EnumMember(
        value = 20L,
        name = "NFSERR_NOTDIR"
    )
    NFSERR_NOTDIR,

    /**
     * {@code NFSERR_ISDIR = 21}
     */
    @EnumMember(
        value = 21L,
        name = "NFSERR_ISDIR"
    )
    NFSERR_ISDIR,

    /**
     * {@code NFSERR_INVAL = 22}
     */
    @EnumMember(
        value = 22L,
        name = "NFSERR_INVAL"
    )
    NFSERR_INVAL,

    /**
     * {@code NFSERR_FBIG = 27}
     */
    @EnumMember(
        value = 27L,
        name = "NFSERR_FBIG"
    )
    NFSERR_FBIG,

    /**
     * {@code NFSERR_NOSPC = 28}
     */
    @EnumMember(
        value = 28L,
        name = "NFSERR_NOSPC"
    )
    NFSERR_NOSPC,

    /**
     * {@code NFSERR_ROFS = 30}
     */
    @EnumMember(
        value = 30L,
        name = "NFSERR_ROFS"
    )
    NFSERR_ROFS,

    /**
     * {@code NFSERR_MLINK = 31}
     */
    @EnumMember(
        value = 31L,
        name = "NFSERR_MLINK"
    )
    NFSERR_MLINK,

    /**
     * {@code NFSERR_NAMETOOLONG = 63}
     */
    @EnumMember(
        value = 63L,
        name = "NFSERR_NAMETOOLONG"
    )
    NFSERR_NAMETOOLONG,

    /**
     * {@code NFSERR_NOTEMPTY = 66}
     */
    @EnumMember(
        value = 66L,
        name = "NFSERR_NOTEMPTY"
    )
    NFSERR_NOTEMPTY,

    /**
     * {@code NFSERR_DQUOT = 69}
     */
    @EnumMember(
        value = 69L,
        name = "NFSERR_DQUOT"
    )
    NFSERR_DQUOT,

    /**
     * {@code NFSERR_STALE = 70}
     */
    @EnumMember(
        value = 70L,
        name = "NFSERR_STALE"
    )
    NFSERR_STALE,

    /**
     * {@code NFSERR_REMOTE = 71}
     */
    @EnumMember(
        value = 71L,
        name = "NFSERR_REMOTE"
    )
    NFSERR_REMOTE,

    /**
     * {@code NFSERR_WFLUSH = 99}
     */
    @EnumMember(
        value = 99L,
        name = "NFSERR_WFLUSH"
    )
    NFSERR_WFLUSH,

    /**
     * {@code NFSERR_BADHANDLE = 10001}
     */
    @EnumMember(
        value = 10001L,
        name = "NFSERR_BADHANDLE"
    )
    NFSERR_BADHANDLE,

    /**
     * {@code NFSERR_NOT_SYNC = 10002}
     */
    @EnumMember(
        value = 10002L,
        name = "NFSERR_NOT_SYNC"
    )
    NFSERR_NOT_SYNC,

    /**
     * {@code NFSERR_BAD_COOKIE = 10003}
     */
    @EnumMember(
        value = 10003L,
        name = "NFSERR_BAD_COOKIE"
    )
    NFSERR_BAD_COOKIE,

    /**
     * {@code NFSERR_NOTSUPP = 10004}
     */
    @EnumMember(
        value = 10004L,
        name = "NFSERR_NOTSUPP"
    )
    NFSERR_NOTSUPP,

    /**
     * {@code NFSERR_TOOSMALL = 10005}
     */
    @EnumMember(
        value = 10005L,
        name = "NFSERR_TOOSMALL"
    )
    NFSERR_TOOSMALL,

    /**
     * {@code NFSERR_SERVERFAULT = 10006}
     */
    @EnumMember(
        value = 10006L,
        name = "NFSERR_SERVERFAULT"
    )
    NFSERR_SERVERFAULT,

    /**
     * {@code NFSERR_BADTYPE = 10007}
     */
    @EnumMember(
        value = 10007L,
        name = "NFSERR_BADTYPE"
    )
    NFSERR_BADTYPE,

    /**
     * {@code NFSERR_JUKEBOX = 10008}
     */
    @EnumMember(
        value = 10008L,
        name = "NFSERR_JUKEBOX"
    )
    NFSERR_JUKEBOX,

    /**
     * {@code NFSERR_SAME = 10009}
     */
    @EnumMember(
        value = 10009L,
        name = "NFSERR_SAME"
    )
    NFSERR_SAME,

    /**
     * {@code NFSERR_DENIED = 10010}
     */
    @EnumMember(
        value = 10010L,
        name = "NFSERR_DENIED"
    )
    NFSERR_DENIED,

    /**
     * {@code NFSERR_EXPIRED = 10011}
     */
    @EnumMember(
        value = 10011L,
        name = "NFSERR_EXPIRED"
    )
    NFSERR_EXPIRED,

    /**
     * {@code NFSERR_LOCKED = 10012}
     */
    @EnumMember(
        value = 10012L,
        name = "NFSERR_LOCKED"
    )
    NFSERR_LOCKED,

    /**
     * {@code NFSERR_GRACE = 10013}
     */
    @EnumMember(
        value = 10013L,
        name = "NFSERR_GRACE"
    )
    NFSERR_GRACE,

    /**
     * {@code NFSERR_FHEXPIRED = 10014}
     */
    @EnumMember(
        value = 10014L,
        name = "NFSERR_FHEXPIRED"
    )
    NFSERR_FHEXPIRED,

    /**
     * {@code NFSERR_SHARE_DENIED = 10015}
     */
    @EnumMember(
        value = 10015L,
        name = "NFSERR_SHARE_DENIED"
    )
    NFSERR_SHARE_DENIED,

    /**
     * {@code NFSERR_WRONGSEC = 10016}
     */
    @EnumMember(
        value = 10016L,
        name = "NFSERR_WRONGSEC"
    )
    NFSERR_WRONGSEC,

    /**
     * {@code NFSERR_CLID_INUSE = 10017}
     */
    @EnumMember(
        value = 10017L,
        name = "NFSERR_CLID_INUSE"
    )
    NFSERR_CLID_INUSE,

    /**
     * {@code NFSERR_RESOURCE = 10018}
     */
    @EnumMember(
        value = 10018L,
        name = "NFSERR_RESOURCE"
    )
    NFSERR_RESOURCE,

    /**
     * {@code NFSERR_MOVED = 10019}
     */
    @EnumMember(
        value = 10019L,
        name = "NFSERR_MOVED"
    )
    NFSERR_MOVED,

    /**
     * {@code NFSERR_NOFILEHANDLE = 10020}
     */
    @EnumMember(
        value = 10020L,
        name = "NFSERR_NOFILEHANDLE"
    )
    NFSERR_NOFILEHANDLE,

    /**
     * {@code NFSERR_MINOR_VERS_MISMATCH = 10021}
     */
    @EnumMember(
        value = 10021L,
        name = "NFSERR_MINOR_VERS_MISMATCH"
    )
    NFSERR_MINOR_VERS_MISMATCH,

    /**
     * {@code NFSERR_STALE_CLIENTID = 10022}
     */
    @EnumMember(
        value = 10022L,
        name = "NFSERR_STALE_CLIENTID"
    )
    NFSERR_STALE_CLIENTID,

    /**
     * {@code NFSERR_STALE_STATEID = 10023}
     */
    @EnumMember(
        value = 10023L,
        name = "NFSERR_STALE_STATEID"
    )
    NFSERR_STALE_STATEID,

    /**
     * {@code NFSERR_OLD_STATEID = 10024}
     */
    @EnumMember(
        value = 10024L,
        name = "NFSERR_OLD_STATEID"
    )
    NFSERR_OLD_STATEID,

    /**
     * {@code NFSERR_BAD_STATEID = 10025}
     */
    @EnumMember(
        value = 10025L,
        name = "NFSERR_BAD_STATEID"
    )
    NFSERR_BAD_STATEID,

    /**
     * {@code NFSERR_BAD_SEQID = 10026}
     */
    @EnumMember(
        value = 10026L,
        name = "NFSERR_BAD_SEQID"
    )
    NFSERR_BAD_SEQID,

    /**
     * {@code NFSERR_NOT_SAME = 10027}
     */
    @EnumMember(
        value = 10027L,
        name = "NFSERR_NOT_SAME"
    )
    NFSERR_NOT_SAME,

    /**
     * {@code NFSERR_LOCK_RANGE = 10028}
     */
    @EnumMember(
        value = 10028L,
        name = "NFSERR_LOCK_RANGE"
    )
    NFSERR_LOCK_RANGE,

    /**
     * {@code NFSERR_SYMLINK = 10029}
     */
    @EnumMember(
        value = 10029L,
        name = "NFSERR_SYMLINK"
    )
    NFSERR_SYMLINK,

    /**
     * {@code NFSERR_RESTOREFH = 10030}
     */
    @EnumMember(
        value = 10030L,
        name = "NFSERR_RESTOREFH"
    )
    NFSERR_RESTOREFH,

    /**
     * {@code NFSERR_LEASE_MOVED = 10031}
     */
    @EnumMember(
        value = 10031L,
        name = "NFSERR_LEASE_MOVED"
    )
    NFSERR_LEASE_MOVED,

    /**
     * {@code NFSERR_ATTRNOTSUPP = 10032}
     */
    @EnumMember(
        value = 10032L,
        name = "NFSERR_ATTRNOTSUPP"
    )
    NFSERR_ATTRNOTSUPP,

    /**
     * {@code NFSERR_NO_GRACE = 10033}
     */
    @EnumMember(
        value = 10033L,
        name = "NFSERR_NO_GRACE"
    )
    NFSERR_NO_GRACE,

    /**
     * {@code NFSERR_RECLAIM_BAD = 10034}
     */
    @EnumMember(
        value = 10034L,
        name = "NFSERR_RECLAIM_BAD"
    )
    NFSERR_RECLAIM_BAD,

    /**
     * {@code NFSERR_RECLAIM_CONFLICT = 10035}
     */
    @EnumMember(
        value = 10035L,
        name = "NFSERR_RECLAIM_CONFLICT"
    )
    NFSERR_RECLAIM_CONFLICT,

    /**
     * {@code NFSERR_BAD_XDR = 10036}
     */
    @EnumMember(
        value = 10036L,
        name = "NFSERR_BAD_XDR"
    )
    NFSERR_BAD_XDR,

    /**
     * {@code NFSERR_LOCKS_HELD = 10037}
     */
    @EnumMember(
        value = 10037L,
        name = "NFSERR_LOCKS_HELD"
    )
    NFSERR_LOCKS_HELD,

    /**
     * {@code NFSERR_OPENMODE = 10038}
     */
    @EnumMember(
        value = 10038L,
        name = "NFSERR_OPENMODE"
    )
    NFSERR_OPENMODE,

    /**
     * {@code NFSERR_BADOWNER = 10039}
     */
    @EnumMember(
        value = 10039L,
        name = "NFSERR_BADOWNER"
    )
    NFSERR_BADOWNER,

    /**
     * {@code NFSERR_BADCHAR = 10040}
     */
    @EnumMember(
        value = 10040L,
        name = "NFSERR_BADCHAR"
    )
    NFSERR_BADCHAR,

    /**
     * {@code NFSERR_BADNAME = 10041}
     */
    @EnumMember(
        value = 10041L,
        name = "NFSERR_BADNAME"
    )
    NFSERR_BADNAME,

    /**
     * {@code NFSERR_BAD_RANGE = 10042}
     */
    @EnumMember(
        value = 10042L,
        name = "NFSERR_BAD_RANGE"
    )
    NFSERR_BAD_RANGE,

    /**
     * {@code NFSERR_LOCK_NOTSUPP = 10043}
     */
    @EnumMember(
        value = 10043L,
        name = "NFSERR_LOCK_NOTSUPP"
    )
    NFSERR_LOCK_NOTSUPP,

    /**
     * {@code NFSERR_OP_ILLEGAL = 10044}
     */
    @EnumMember(
        value = 10044L,
        name = "NFSERR_OP_ILLEGAL"
    )
    NFSERR_OP_ILLEGAL,

    /**
     * {@code NFSERR_DEADLOCK = 10045}
     */
    @EnumMember(
        value = 10045L,
        name = "NFSERR_DEADLOCK"
    )
    NFSERR_DEADLOCK,

    /**
     * {@code NFSERR_FILE_OPEN = 10046}
     */
    @EnumMember(
        value = 10046L,
        name = "NFSERR_FILE_OPEN"
    )
    NFSERR_FILE_OPEN,

    /**
     * {@code NFSERR_ADMIN_REVOKED = 10047}
     */
    @EnumMember(
        value = 10047L,
        name = "NFSERR_ADMIN_REVOKED"
    )
    NFSERR_ADMIN_REVOKED,

    /**
     * {@code NFSERR_CB_PATH_DOWN = 10048}
     */
    @EnumMember(
        value = 10048L,
        name = "NFSERR_CB_PATH_DOWN"
    )
    NFSERR_CB_PATH_DOWN
  }
}
