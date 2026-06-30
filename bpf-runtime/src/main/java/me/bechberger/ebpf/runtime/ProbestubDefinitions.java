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
 * Generated class for BPF runtime types that start with probestub
 */
@java.lang.SuppressWarnings("unused")
public final class ProbestubDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ack_update_msk(Ptr<?> __data, @Unsigned long data_ack,
      @Unsigned long old_snd_una, @Unsigned long new_snd_una, @Unsigned long new_wnd_end,
      @Unsigned long msk_wnd_end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_add_device_to_group(Ptr<?> __data, int group_id, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_aer_event($arg1, (const u8 *)$arg2, (const unsigned int)$arg3, (const u8)$arg4, (const u8)$arg5, $arg6)")
  public static void __probestub_aer_event(Ptr<?> __data, String dev_name, @Unsigned int status,
      char severity, char tlp_header_valid, Ptr<pcie_tlp_log> tlp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_alarmtimer_cancel(Ptr<?> __data, Ptr<alarm> alarm,
      @OriginalName("ktime_t") long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_alarmtimer_fired(Ptr<?> __data, Ptr<alarm> alarm,
      @OriginalName("ktime_t") long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_alarmtimer_start(Ptr<?> __data, Ptr<alarm> alarm,
      @OriginalName("ktime_t") long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_alarmtimer_suspend(Ptr<?> __data,
      @OriginalName("ktime_t") long expires, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_alloc_vmap_area(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long size, @Unsigned long align, @Unsigned long vstart, @Unsigned long vend,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_amd_pstate_epp_perf(Ptr<?> __data, @Unsigned int cpu_id,
      char highest_perf, char epp, char min_perf, char max_perf, boolean boost, boolean changed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_amd_pstate_perf(Ptr<?> __data, char min_perf, char target_perf,
      char capacity, @Unsigned long freq, @Unsigned long mperf, @Unsigned long aperf,
      @Unsigned long tsc, @Unsigned int cpu_id, boolean fast_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_arm_event($arg1, (const struct cper_sec_proc_arm *)$arg2, (const u8 *)$arg3, (const unsigned int)$arg4, (const u8 *)$arg5, (const unsigned int)$arg6, (const u8 *)$arg7, (const unsigned int)$arg8, $arg9, $arg10)")
  public static void __probestub_arm_event(Ptr<?> __data, Ptr<cper_sec_proc_arm> proc,
      Ptr<java.lang.Character> pei_err, @Unsigned int pei_len, Ptr<java.lang.Character> ctx_err,
      @Unsigned int ctx_len, Ptr<java.lang.Character> oem, @Unsigned int oem_len, char sev,
      int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ata_bmdma_setup($arg1, $arg2, (const struct ata_taskfile *)$arg3, $arg4)")
  public static void __probestub_ata_bmdma_setup(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ata_bmdma_start($arg1, $arg2, (const struct ata_taskfile *)$arg3, $arg4)")
  public static void __probestub_ata_bmdma_start(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_bmdma_status(Ptr<?> __data, Ptr<ata_port> ap,
      @Unsigned int host_stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ata_bmdma_stop($arg1, $arg2, (const struct ata_taskfile *)$arg3, $arg4)")
  public static void __probestub_ata_bmdma_stop(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_eh_about_to_do(Ptr<?> __data, Ptr<ata_link> link,
      @Unsigned int devno, @Unsigned int eh_action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_eh_done(Ptr<?> __data, Ptr<ata_link> link, @Unsigned int devno,
      @Unsigned int eh_action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_eh_link_autopsy(Ptr<?> __data, Ptr<ata_device> dev,
      @Unsigned int eh_action, @Unsigned int eh_err_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_eh_link_autopsy_qc(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ata_exec_command($arg1, $arg2, (const struct ata_taskfile *)$arg3, $arg4)")
  public static void __probestub_ata_exec_command(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_link_hardreset_begin(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_link_hardreset_end(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_link_postreset(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_link_softreset_begin(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_link_softreset_end(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_port_freeze(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_port_thaw(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_qc_complete_done(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_qc_complete_failed(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_qc_complete_internal(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_qc_issue(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_qc_prep(Ptr<?> __data, Ptr<ata_queued_cmd> qc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_sff_flush_pio_task(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_sff_hsm_command_complete(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      char state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_sff_hsm_state(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      char state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_sff_pio_transfer_data(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      @Unsigned int offset, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_sff_port_intr(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      char state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_slave_hardreset_begin(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, @Unsigned long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_slave_hardreset_end(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_slave_postreset(Ptr<?> __data, Ptr<ata_link> link,
      Ptr<java.lang. @Unsigned Integer> _class, int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ata_std_sched_eh(Ptr<?> __data, Ptr<ata_port> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ata_tf_load($arg1, $arg2, (const struct ata_taskfile *)$arg3)")
  public static void __probestub_ata_tf_load(Ptr<?> __data, Ptr<ata_port> ap,
      Ptr<ata_taskfile> tf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_atapi_pio_transfer_data(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      @Unsigned int offset, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_atapi_send_cdb(Ptr<?> __data, Ptr<ata_queued_cmd> qc,
      @Unsigned int offset, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_attach_device_to_domain(Ptr<?> __data, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_balance_dirty_pages(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<dirty_throttle_control> dtc, @Unsigned long dirty_ratelimit,
      @Unsigned long task_ratelimit, @Unsigned long dirtied, @Unsigned long period, long pause,
      @Unsigned long start_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_bdi_dirty_ratelimit(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned long dirty_rate, @Unsigned long task_ratelimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_blk_zone_append_update_request_bio(Ptr<?> __data,
      Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_blk_zone_wplug_bio(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int zno, @Unsigned @OriginalName("sector_t") long sector,
      @Unsigned int nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_blkdev_zone_mgmt(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("sector_t") long nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_bio_backmerge(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_bio_complete(Ptr<?> __data, Ptr<request_queue> q,
      Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_bio_frontmerge(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_bio_queue(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_bio_remap(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_dirty_buffer(Ptr<?> __data, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_getrq(Ptr<?> __data, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_io_done(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_io_start(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_plug(Ptr<?> __data, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_complete(Ptr<?> __data, Ptr<request> rq,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_error(Ptr<?> __data, Ptr<request> rq,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_insert(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_issue(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_merge(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_remap(Ptr<?> __data, Ptr<request> rq,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_rq_requeue(Ptr<?> __data, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_split(Ptr<?> __data, Ptr<bio> bio,
      @Unsigned int new_sector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_touch_buffer(Ptr<?> __data, Ptr<buffer_head> bh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_block_unplug(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int depth, boolean explicit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_bpf_test_finish(Ptr<?> __data, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_bpf_trace_printk($arg1, (const u8 *)$arg2)")
  public static void __probestub_bpf_trace_printk(Ptr<?> __data, String bpf_string) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_bpf_trigger_tp(Ptr<?> __data, int nonce) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_bpf_xdp_link_attach_failed($arg1, (const u8 *)$arg2)")
  public static void __probestub_bpf_xdp_link_attach_failed(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_br_fdb_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void __probestub_br_fdb_add(Ptr<?> __data, Ptr<ndmsg> ndm, Ptr<net_device> dev,
      String addr, @Unsigned short vid, @Unsigned short nlh_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_br_fdb_external_learn_add($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5)")
  public static void __probestub_br_fdb_external_learn_add(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> p, String addr, @Unsigned short vid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_br_fdb_update($arg1, $arg2, $arg3, (const u8 *)$arg4, $arg5, $arg6)")
  public static void __probestub_br_fdb_update(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_port> source, String addr, @Unsigned short vid, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_br_mdb_full($arg1, (const struct net_device *)$arg2, (const struct br_ip *)$arg3)")
  public static void __probestub_br_mdb_full(Ptr<?> __data, Ptr<net_device> dev, Ptr<br_ip> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_break_lease_block(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_break_lease_noblock(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_break_lease_unblock(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cache_tag_assign(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cache_tag_flush_range(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cache_tag_flush_range_np(Ptr<?> __data, Ptr<cache_tag> tag,
      @Unsigned long start, @Unsigned long end, @Unsigned long addr, @Unsigned long pages,
      @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cache_tag_unassign(Ptr<?> __data, Ptr<cache_tag> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_call_function_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_call_function_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_call_function_single_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_call_function_single_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cap_capable($arg1, (const struct cred *)$arg2, $arg3, (const struct user_namespace *)$arg4, $arg5, $arg6)")
  public static void __probestub_cap_capable(Ptr<?> __data, Ptr<cred> cred,
      Ptr<user_namespace> target_ns, Ptr<user_namespace> capable_ns, int cap, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cdev_update(Ptr<?> __data, Ptr<thermal_cooling_device> cdev,
      @Unsigned long target) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_attach_task($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void __probestub_cgroup_attach_task(Ptr<?> __data, Ptr<cgroup> dst_cgrp,
      String path, Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_destroy_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_freeze($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_freeze(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_mkdir($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_mkdir(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_notify_frozen($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_cgroup_notify_frozen(Ptr<?> __data, Ptr<cgroup> cgrp, String path,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_notify_populated($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_cgroup_notify_populated(Ptr<?> __data, Ptr<cgroup> cgrp,
      String path, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_release($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_release(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_remount(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_rename($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_rename(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_rmdir($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_rmdir(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_rstat_lock_contended(Ptr<?> __data, Ptr<cgroup> cgrp,
      int cpu, boolean contended) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_rstat_locked(Ptr<?> __data, Ptr<cgroup> cgrp, int cpu,
      boolean contended) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_rstat_unlock(Ptr<?> __data, Ptr<cgroup> cgrp, int cpu,
      boolean contended) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cgroup_setup_root(Ptr<?> __data, Ptr<cgroup_root> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_transfer_tasks($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void __probestub_cgroup_transfer_tasks(Ptr<?> __data, Ptr<cgroup> dst_cgrp,
      String path, Ptr<task_struct> task, boolean threadgroup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cgroup_unfreeze($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_cgroup_unfreeze(Ptr<?> __data, Ptr<cgroup> cgrp, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_disable(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_disable_complete(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_enable(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_enable_complete(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_prepare(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_prepare_complete(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_rate_request_done(Ptr<?> __data, Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_rate_request_start(Ptr<?> __data, Ptr<clk_rate_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_duty_cycle(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_duty_cycle_complete(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_duty> duty) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_max_rate(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_min_rate(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_parent(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_parent_complete(Ptr<?> __data, Ptr<clk_core> core,
      Ptr<clk_core> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_phase(Ptr<?> __data, Ptr<clk_core> core, int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_phase_complete(Ptr<?> __data, Ptr<clk_core> core,
      int phase) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_rate(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_rate_complete(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_set_rate_range(Ptr<?> __data, Ptr<clk_core> core,
      @Unsigned long min, @Unsigned long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_unprepare(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_clk_unprepare_complete(Ptr<?> __data, Ptr<clk_core> core) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cma_alloc_busy_retry($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6)")
  public static void __probestub_cma_alloc_busy_retry(Ptr<?> __data, String name,
      @Unsigned long pfn, Ptr<page> page, @Unsigned long count, @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cma_alloc_finish($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5, $arg6, $arg7)")
  public static void __probestub_cma_alloc_finish(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count, @Unsigned int align, int errorno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cma_alloc_start($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_cma_alloc_start(Ptr<?> __data, String name, @Unsigned long count,
      @Unsigned int align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cma_release($arg1, (const u8 *)$arg2, $arg3, (const struct page *)$arg4, $arg5)")
  public static void __probestub_cma_release(Ptr<?> __data, String name, @Unsigned long pfn,
      Ptr<page> page, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_compact_retry(Ptr<?> __data, int order, compact_priority priority,
      compact_result result, int retries, int max_retries, boolean ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_console($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_console(Ptr<?> __data, String text, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_consume_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_contention_begin(Ptr<?> __data, Ptr<?> lock, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_contention_end(Ptr<?> __data, Ptr<?> lock, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_count_memcg_events(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      @Unsigned long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cpu_frequency(Ptr<?> __data, @Unsigned int frequency,
      @Unsigned int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cpu_frequency_limits(Ptr<?> __data, Ptr<cpufreq_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cpu_idle(Ptr<?> __data, @Unsigned int state,
      @Unsigned int cpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cpu_idle_miss(Ptr<?> __data, @Unsigned int cpu_id,
      @Unsigned int state, boolean below) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cpuhp_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int))$arg5)")
  public static void __probestub_cpuhp_enter(Ptr<?> __data, @Unsigned int cpu, int target, int idx,
      Ptr<?> fun) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_cpuhp_exit(Ptr<?> __data, @Unsigned int cpu, int state, int idx,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_cpuhp_multi_enter($arg1, $arg2, $arg3, $arg4, (int (*)(unsigned int, struct hlist_node*))$arg5, $arg6)")
  public static void __probestub_cpuhp_multi_enter(Ptr<?> __data, @Unsigned int cpu, int target,
      int idx, Ptr<?> fun, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_csd_function_entry(Ptr<?> __data,
      @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_csd_function_exit(Ptr<?> __data,
      @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_csd_queue_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_csd_queue_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, @OriginalName("smp_call_func_t") Ptr<?> func,
      Ptr<@OriginalName("call_single_data_t") __call_single_data> csd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ctime_ns_xchg(Ptr<?> __data, Ptr<inode> inode, @Unsigned int old,
      @Unsigned int _new, @Unsigned int cur) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ctime_xchg_skip(Ptr<?> __data, Ptr<inode> inode,
      Ptr<timespec64> ctime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_insert_pfn_mkwrite(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_insert_pfn_mkwrite_no_entry(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_load_hole(Ptr<?> __data, Ptr<inode> inode, Ptr<vm_fault> vmf,
      int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pmd_fault(Ptr<?> __data, Ptr<inode> inode, Ptr<vm_fault> vmf,
      @Unsigned long max_pgoff, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pmd_fault_done(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, @Unsigned long max_pgoff, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pmd_load_hole(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, Ptr<folio> zero_folio, Ptr<?> radix_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pmd_load_hole_fallback(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, Ptr<folio> zero_folio, Ptr<?> radix_entry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pte_fault(Ptr<?> __data, Ptr<inode> inode, Ptr<vm_fault> vmf,
      int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_pte_fault_done(Ptr<?> __data, Ptr<inode> inode,
      Ptr<vm_fault> vmf, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_writeback_one(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pgoff, @Unsigned long pglen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_writeback_range(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long start_index, @Unsigned long end_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dax_writeback_range_done(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long start_index, @Unsigned long end_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_deferred_error_apic_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_deferred_error_apic_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_dev_pm_qos_add_request($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_dev_pm_qos_add_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_dev_pm_qos_remove_request($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_dev_pm_qos_remove_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_dev_pm_qos_update_request($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_dev_pm_qos_update_request(Ptr<?> __data, String name,
      dev_pm_qos_req_type type, int new_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_devfreq_frequency(Ptr<?> __data, Ptr<devfreq> devfreq,
      @Unsigned long freq, @Unsigned long prev_freq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_devfreq_monitor(Ptr<?> __data, Ptr<devfreq> devfreq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_device_pm_callback_end(Ptr<?> __data, Ptr<device> dev, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_device_pm_callback_start($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_device_pm_callback_start(Ptr<?> __data, Ptr<device> dev,
      String pm_ops, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_health_recover_aborted($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void __probestub_devlink_health_recover_aborted(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, boolean health_state, @Unsigned long time_since_last_recover) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_health_report($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void __probestub_devlink_health_report(Ptr<?> __data, Ptr<devlink> devlink,
      String reporter_name, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_health_reporter_state_update($arg1, (const struct devlink *)$arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_devlink_health_reporter_state_update(Ptr<?> __data,
      Ptr<devlink> devlink, String reporter_name, boolean new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_hwerr($arg1, (const struct devlink *)$arg2, $arg3, (const u8 *)$arg4)")
  public static void __probestub_devlink_hwerr(Ptr<?> __data, Ptr<devlink> devlink, int err,
      String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_hwmsg($arg1, (const struct devlink *)$arg2, $arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void __probestub_devlink_hwmsg(Ptr<?> __data, Ptr<devlink> devlink,
      boolean incoming, @Unsigned long type, Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devlink_trap_report($arg1, (const struct devlink *)$arg2, $arg3, (const struct devlink_trap_metadata *)$arg4)")
  public static void __probestub_devlink_trap_report(Ptr<?> __data, Ptr<devlink> devlink,
      Ptr<sk_buff> skb, Ptr<devlink_trap_metadata> metadata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_devres_log($arg1, $arg2, (const u8 *)$arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static void __probestub_devres_log(Ptr<?> __data, Ptr<device> dev, String op, Ptr<?> node,
      String name, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_disk_zone_wplug_add_bio(Ptr<?> __data, Ptr<request_queue> q,
      @Unsigned int zno, @Unsigned @OriginalName("sector_t") long sector,
      @Unsigned int nr_sectors) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_alloc(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_alloc_pages(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_alloc_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_alloc_sgt_err(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int flags, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_destroy(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_emit(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_enable_signal(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_init(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_signaled(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_wait_end(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_fence_wait_start(Ptr<?> __data, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_free(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_free_pages(Ptr<?> __data, Ptr<device> dev, Ptr<?> virt_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_free_sgt(Ptr<?> __data, Ptr<device> dev, Ptr<sg_table> sgt,
      @Unsigned long size, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_map_page(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_map_resource(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_map_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, int ents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_map_sg_err(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sgl, int nents, int err, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_sync_sg_for_cpu(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sg, int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_sync_sg_for_device(Ptr<?> __data, Ptr<device> dev,
      Ptr<scatterlist> sg, int nents, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_sync_single_for_cpu(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_sync_single_for_device(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_unmap_page(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_unmap_resource(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dma_unmap_sg(Ptr<?> __data, Ptr<device> dev, Ptr<scatterlist> sgl,
      int nents, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_dql_stall_detected(Ptr<?> __data, @Unsigned short thrs,
      @Unsigned int len, @Unsigned long last_reap, @Unsigned long hist_head, @Unsigned long now,
      Ptr<java.lang. @Unsigned Long> hist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_drm_vblank_event(Ptr<?> __data, int crtc, @Unsigned int seq,
      @OriginalName("ktime_t") long time, boolean high_prec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_drm_vblank_event_delivered(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_drm_vblank_event_queued(Ptr<?> __data, Ptr<drm_file> file,
      int crtc, @Unsigned int seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_emulate_vsyscall(Ptr<?> __data, int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_error_apic_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_error_apic_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_error_report_end(Ptr<?> __data, error_detector error_detector,
      @Unsigned long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_error_wwnr(Ptr<?> __data, int id, String state, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_event_wwnr(Ptr<?> __data, int id, String state, String event,
      String next_state, boolean final_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_exit_mmap(Ptr<?> __data, Ptr<mm_struct> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_alloc_da_blocks(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_allocate_blocks(Ptr<?> __data,
      Ptr<ext4_allocation_request> ar, @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_allocate_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_begin_ordered_truncate(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long new_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_collapse_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_release_space(Ptr<?> __data, Ptr<inode> inode,
      int freed_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int nr_resv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_update_reserve_space(Ptr<?> __data, Ptr<inode> inode,
      int used_blocks, int quota_claim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_write_begin(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_write_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_write_folios_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_write_folios_start(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long start_pos, @OriginalName("loff_t") long next_pos,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_da_write_pages_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_discard_blocks(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long blk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_discard_preallocations(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_drop_inode(Ptr<?> __data, Ptr<inode> inode, int drop) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ext4_error($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_ext4_error(Ptr<?> __data, Ptr<super_block> sb, String function,
      @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_cache_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_find_extent_range_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_find_extent_range_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_insert_delayed_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, boolean lclu_allocated, boolean end_allocated) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_insert_extent(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_lookup_extent_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_lookup_extent_exit(Ptr<?> __data, Ptr<inode> inode,
      Ptr<extent_status> es, int found) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_remove_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_lblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_shrink(Ptr<?> __data, Ptr<super_block> sb, int nr_shrunk,
      @Unsigned long scan_time, int nr_skipped, int retried) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_shrink_count(Ptr<?> __data, Ptr<super_block> sb,
      int nr_to_scan, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_shrink_scan_enter(Ptr<?> __data, Ptr<super_block> sb,
      int nr_to_scan, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_es_shrink_scan_exit(Ptr<?> __data, Ptr<super_block> sb,
      int nr_shrunk, int cache_cnt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_evict_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_convert_to_initialized_enter(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_convert_to_initialized_fastpath(Ptr<?> __data,
      Ptr<inode> inode, Ptr<ext4_map_blocks> map, Ptr<ext4_extent> ux, Ptr<ext4_extent> ix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_handle_unwritten_extents(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_map_blocks> map, int flags, @Unsigned int allocated,
      @Unsigned @OriginalName("ext4_fsblk_t") long newblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_load_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_map_blocks_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk, @Unsigned int len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_map_blocks_exit(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int flags, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_remove_space(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_remove_space_done(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start,
      @Unsigned @OriginalName("ext4_lblk_t") int end, int depth, Ptr<partial_cluster> pc,
      @Unsigned @OriginalName("__le16") short eh_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_rm_idx(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_rm_leaf(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int start, Ptr<ext4_extent> ex,
      Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ext_show_extent(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk,
      @Unsigned @OriginalName("ext4_fsblk_t") long pblk, @Unsigned short len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fallocate_enter(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fallocate_exit(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @Unsigned int max_blocks, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_cleanup(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int full,
      @Unsigned @OriginalName("tid_t") int tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_commit_start(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_commit_stop(Ptr<?> __data, Ptr<super_block> sb, int nblks,
      int reason, @Unsigned @OriginalName("tid_t") int commit_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_replay(Ptr<?> __data, Ptr<super_block> sb, int tag,
      int ino, int priv1, int priv2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_replay_scan(Ptr<?> __data, Ptr<super_block> sb, int error,
      int off) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_stats(Ptr<?> __data, Ptr<super_block> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_track_create(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_track_inode(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_track_link(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_track_range(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode, long start,
      long end, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fc_track_unlink(Ptr<?> __data,
      Ptr<@OriginalName("handle_t") jbd2_journal_handle> handle, Ptr<inode> inode,
      Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_forget(Ptr<?> __data, Ptr<inode> inode, int is_metadata,
      @Unsigned long block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_free_blocks(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long block, @Unsigned long count, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_free_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fsmap_high_key(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned int keydev, @Unsigned int agno, @Unsigned long bno, @Unsigned long len,
      @Unsigned long owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fsmap_low_key(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned int keydev, @Unsigned int agno, @Unsigned long bno, @Unsigned long len,
      @Unsigned long owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_fsmap_mapping(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned int keydev, @Unsigned int agno, @Unsigned long bno, @Unsigned long len,
      @Unsigned long owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_get_implied_cluster_alloc_exit(Ptr<?> __data,
      Ptr<super_block> sb, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_getfsmap_high_key(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_fsmap> fsmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_getfsmap_low_key(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_fsmap> fsmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_getfsmap_mapping(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_fsmap> fsmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ind_map_blocks_enter(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ext4_lblk_t") int lblk, @Unsigned int len, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_ind_map_blocks_exit(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned int flags, Ptr<ext4_map_blocks> map, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_insert_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_invalidate_folio(Ptr<?> __data, Ptr<folio> folio,
      @Unsigned long offset, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_journal_start_inode(Ptr<?> __data, Ptr<inode> inode,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_journal_start_reserved(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_journal_start_sb(Ptr<?> __data, Ptr<super_block> sb,
      int blocks, int rsv_blocks, int revoke_creds, int type, @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_journalled_invalidate_folio(Ptr<?> __data, Ptr<folio> folio,
      @Unsigned long offset, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_journalled_write_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_lazy_itable_init(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_load_inode(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_load_inode_bitmap(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mark_inode_dirty(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long IP) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_buddy_bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_discard_preallocations(Ptr<?> __data, Ptr<super_block> sb,
      int needed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_new_group_pa(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac, Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_new_inode_pa(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac, Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_release_group_pa(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<ext4_prealloc_space> pa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mb_release_inode_pa(Ptr<?> __data,
      Ptr<ext4_prealloc_space> pa, @Unsigned long block, @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mballoc_alloc(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mballoc_discard(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<inode> inode, @Unsigned @OriginalName("ext4_group_t") int group,
      @OriginalName("ext4_grpblk_t") int start, @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mballoc_free(Ptr<?> __data, Ptr<super_block> sb,
      Ptr<inode> inode, @Unsigned @OriginalName("ext4_group_t") int group,
      @OriginalName("ext4_grpblk_t") int start, @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_mballoc_prealloc(Ptr<?> __data,
      Ptr<ext4_allocation_context> ac) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_nfs_commit_metadata(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_other_inode_update_time(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned @OriginalName("ino_t") long orig_ino) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_prefetch_bitmaps(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group,
      @Unsigned @OriginalName("ext4_group_t") int next, @Unsigned int prefetch_ios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_punch_hole(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_read_block_bitmap_load(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long group, boolean prefetch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_read_folio(Ptr<?> __data, Ptr<inode> inode,
      Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_release_folio(Ptr<?> __data, Ptr<inode> inode,
      Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_remove_blocks(Ptr<?> __data, Ptr<inode> inode,
      Ptr<ext4_extent> ex, @Unsigned @OriginalName("ext4_lblk_t") int from,
      @Unsigned @OriginalName("ext4_fsblk_t") long to, Ptr<partial_cluster> pc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_request_blocks(Ptr<?> __data,
      Ptr<ext4_allocation_request> ar) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_request_inode(Ptr<?> __data, Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_shutdown(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_sync_file_enter(Ptr<?> __data, Ptr<file> file, int datasync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_sync_file_exit(Ptr<?> __data, Ptr<inode> inode, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_sync_fs(Ptr<?> __data, Ptr<super_block> sb, int wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_trim_all_free(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_trim_extent(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_group_t") int group, @OriginalName("ext4_grpblk_t") int start,
      @OriginalName("ext4_grpblk_t") int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_truncate_enter(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_truncate_exit(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_unlink_enter(Ptr<?> __data, Ptr<inode> parent,
      Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_unlink_exit(Ptr<?> __data, Ptr<dentry> dentry, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_update_sb(Ptr<?> __data, Ptr<super_block> sb,
      @Unsigned @OriginalName("ext4_fsblk_t") long fsblk, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_write_begin(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_write_end(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long pos, @Unsigned int len, @Unsigned int copied) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_writepages(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_writepages_result(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, int ret, int pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ext4_zero_range(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_extlog_mem_event($arg1, $arg2, $arg3, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg4, (const u8 *)$arg5, $arg6)")
  public static void __probestub_extlog_mem_event(Ptr<?> __data, Ptr<cper_sec_mem_err> mem,
      @Unsigned int err_seq, Ptr<@OriginalName("guid_t") uuid_t> fru_id, String fru_text,
      char sev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_fcntl_setlk(Ptr<?> __data, Ptr<inode> inode, Ptr<file_lock> fl,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_fdb_delete(Ptr<?> __data, Ptr<net_bridge> br,
      Ptr<net_bridge_fdb_entry> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_fib6_table_lookup($arg1, (const struct net *)$arg2, (const struct fib6_result *)$arg3, $arg4, (const struct flowi6 *)$arg5)")
  public static void __probestub_fib6_table_lookup(Ptr<?> __data, Ptr<net> net,
      Ptr<fib6_result> res, Ptr<fib6_table> table, Ptr<flowi6> flp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_fib_table_lookup($arg1, $arg2, (const struct flowi4 *)$arg3, (const struct fib_nh_common *)$arg4, $arg5)")
  public static void __probestub_fib_table_lookup(Ptr<?> __data, @Unsigned int tb_id,
      Ptr<flowi4> flp, Ptr<fib_nh_common> nhc, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_file_check_and_advance_wb_err(Ptr<?> __data, Ptr<file> file,
      @Unsigned @OriginalName("errseq_t") int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_filemap_set_wb_err(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned @OriginalName("errseq_t") int eseq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_fill_mg_cmtime(Ptr<?> __data, Ptr<inode> inode,
      Ptr<timespec64> ctime, Ptr<timespec64> mtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_finish_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_flock_lock_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lock> fl, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_flush_foreign(Ptr<?> __data, Ptr<bdi_writeback> wb,
      @Unsigned int frn_bdi_id, @Unsigned int frn_memcg_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_folio_wait_writeback(Ptr<?> __data, Ptr<folio> folio,
      Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_free_vmap_area_noflush(Ptr<?> __data, @Unsigned long va_start,
      @Unsigned long nr_lazy, @Unsigned long nr_lazy_max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_fuse_request_end($arg1, (const struct fuse_req *)$arg2)")
  public static void __probestub_fuse_request_end(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_fuse_request_send($arg1, (const struct fuse_req *)$arg2)")
  public static void __probestub_fuse_request_send(Ptr<?> __data, Ptr<fuse_req> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_generic_add_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_generic_delete_lease(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_get_mapping_status(Ptr<?> __data, Ptr<mptcp_ext> mpext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_global_dirty_state(Ptr<?> __data, @Unsigned long background_thresh,
      @Unsigned long dirty_thresh) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_gpio_direction(Ptr<?> __data, @Unsigned int gpio, int in,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_gpio_value(Ptr<?> __data, @Unsigned int gpio, int get, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_guest_halt_poll_ns(Ptr<?> __data, boolean grow, @Unsigned int _new,
      @Unsigned int old) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cancel($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4)")
  public static void __probestub_handshake_cancel(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cancel_busy($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4)")
  public static void __probestub_handshake_cancel_busy(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cancel_none($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4)")
  public static void __probestub_handshake_cancel_none(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cmd_accept($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_cmd_accept(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cmd_accept_err($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_cmd_accept_err(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cmd_done($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_cmd_done(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_cmd_done_err($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_cmd_done_err(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_complete($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_complete(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_destruct($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4)")
  public static void __probestub_handshake_destruct(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_notify_err($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_notify_err(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_submit($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4)")
  public static void __probestub_handshake_submit(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_handshake_submit_err($arg1, (const struct net *)$arg2, (const struct handshake_req *)$arg3, (const struct sock *)$arg4, $arg5)")
  public static void __probestub_handshake_submit_err(Ptr<?> __data, Ptr<net> net,
      Ptr<handshake_req> req, Ptr<sock> sk, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hrtimer_cancel(Ptr<?> __data, Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hrtimer_expire_entry(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      Ptr<java.lang. @OriginalName("ktime_t") Long> now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hrtimer_expire_exit(Ptr<?> __data, Ptr<hrtimer> hrtimer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hrtimer_setup(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      @OriginalName("clockid_t") int clockid, hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hrtimer_start(Ptr<?> __data, Ptr<hrtimer> hrtimer,
      hrtimer_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hugetlbfs_alloc_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<inode> dir, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hugetlbfs_evict_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hugetlbfs_fallocate(Ptr<?> __data, Ptr<inode> inode, int mode,
      @OriginalName("loff_t") long offset, @OriginalName("loff_t") long len, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hugetlbfs_free_inode(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hugetlbfs_setattr(Ptr<?> __data, Ptr<inode> inode,
      Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_hwmon_attr_show($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_hwmon_attr_show(Ptr<?> __data, int index, String attr_name,
      long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_hwmon_attr_show_string($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void __probestub_hwmon_attr_show_string(Ptr<?> __data, int index, String attr_name,
      String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_hwmon_attr_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static void __probestub_hwmon_attr_store(Ptr<?> __data, int index, String attr_name,
      long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_hyperv_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, (const struct flush_tlb_info *)$arg3)")
  public static void __probestub_hyperv_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<flush_tlb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hyperv_nested_flush_guest_mapping(Ptr<?> __data, @Unsigned long as,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hyperv_nested_flush_guest_mapping_range(Ptr<?> __data,
      @Unsigned long as, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_hyperv_send_ipi_mask($arg1, (const struct cpumask *)$arg2, $arg3)")
  public static void __probestub_hyperv_send_ipi_mask(Ptr<?> __data, Ptr<cpumask> cpus,
      int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_hyperv_send_ipi_one(Ptr<?> __data, int cpu, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_i2c_read($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void __probestub_i2c_read(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_i2c_reply($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void __probestub_i2c_reply(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_i2c_result($arg1, (const struct i2c_adapter *)$arg2, $arg3, $arg4)")
  public static void __probestub_i2c_result(Ptr<?> __data, Ptr<i2c_adapter> adap, int num,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_i2c_slave($arg1, (const struct i2c_client *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_i2c_slave(Ptr<?> __data, Ptr<i2c_client> client,
      i2c_slave_event event, Ptr<java.lang.Character> val, int cb_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_i2c_write($arg1, (const struct i2c_adapter *)$arg2, (const struct i2c_msg *)$arg3, $arg4)")
  public static void __probestub_i2c_write(Ptr<?> __data, Ptr<i2c_adapter> adap, Ptr<i2c_msg> msg,
      int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_icc_set_bw(Ptr<?> __data, Ptr<icc_path> p, Ptr<icc_node> n, int i,
      @Unsigned int avg_bw, @Unsigned int peak_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_icc_set_bw_end(Ptr<?> __data, Ptr<icc_path> p, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_icmp_send($arg1, (const struct sk_buff *)$arg2, $arg3, $arg4)")
  public static void __probestub_icmp_send(Ptr<?> __data, Ptr<sk_buff> skb, int type, int code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_inet_sk_error_report($arg1, (const struct sock *)$arg2)")
  public static void __probestub_inet_sk_error_report(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_inet_sock_set_state($arg1, (const struct sock *)$arg2, (const int)$arg3, (const int)$arg4)")
  public static void __probestub_inet_sock_set_state(Ptr<?> __data, Ptr<sock> sk, int oldstate,
      int newstate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_initcall_finish(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_initcall_level($arg1, (const u8 *)$arg2)")
  public static void __probestub_initcall_level(Ptr<?> __data, String level) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_initcall_start(Ptr<?> __data,
      @OriginalName("initcall_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_inode_foreign_history(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned int history) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_inode_set_ctime_to_ts(Ptr<?> __data, Ptr<inode> inode,
      Ptr<timespec64> ctime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_inode_switch_wbs(Ptr<?> __data, Ptr<inode> inode,
      Ptr<bdi_writeback> old_wb, Ptr<bdi_writeback> new_wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_page_fault(Ptr<?> __data, Ptr<device> dev, @Unsigned long iova,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_complete(Ptr<?> __data, Ptr<io_ring_ctx> ctx, Ptr<?> req,
      Ptr<io_uring_cqe> cqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_cqe_overflow(Ptr<?> __data, Ptr<?> ctx,
      @Unsigned long user_data, int res, @Unsigned int cflags, Ptr<?> ocqe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_cqring_wait(Ptr<?> __data, Ptr<?> ctx, int min_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_create(Ptr<?> __data, int fd, Ptr<?> ctx,
      @Unsigned int sq_entries, @Unsigned int cq_entries, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_defer(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_fail_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> link) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_file_get(Ptr<?> __data, Ptr<io_kiocb> req, int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_link(Ptr<?> __data, Ptr<io_kiocb> req,
      Ptr<io_kiocb> target_req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_local_work_run(Ptr<?> __data, Ptr<?> ctx, int count,
      @Unsigned int loops) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_poll_arm(Ptr<?> __data, Ptr<io_kiocb> req, int mask,
      int events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_queue_async_work(Ptr<?> __data, Ptr<io_kiocb> req,
      int rw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_register(Ptr<?> __data, Ptr<?> ctx, @Unsigned int opcode,
      @Unsigned int nr_files, @Unsigned int nr_bufs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_io_uring_req_failed($arg1, (const struct io_uring_sqe *)$arg2, $arg3, $arg4)")
  public static void __probestub_io_uring_req_failed(Ptr<?> __data, Ptr<io_uring_sqe> sqe,
      Ptr<io_kiocb> req, int error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_short_write(Ptr<?> __data, Ptr<?> ctx,
      @Unsigned long fpos, @Unsigned long wanted, @Unsigned long got) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_submit_req(Ptr<?> __data, Ptr<io_kiocb> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_task_add(Ptr<?> __data, Ptr<io_kiocb> req, int mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_io_uring_task_work_run(Ptr<?> __data, Ptr<?> tctx,
      @Unsigned int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_inuse_adjust($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_iocost_inuse_adjust(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_inuse_shortage($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_iocost_inuse_shortage(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_inuse_transfer($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_iocost_inuse_transfer(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned int old_inuse, @Unsigned int new_inuse,
      @Unsigned long old_hw_inuse, @Unsigned long new_hw_inuse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iocost_ioc_vrate_adj(Ptr<?> __data, Ptr<ioc> ioc,
      @Unsigned long new_vrate, Ptr<java.lang. @Unsigned Integer> missed_ppm,
      @Unsigned int rq_wait_pct, int nr_lagging, int nr_shortages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_iocg_activate($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __probestub_iocost_iocg_activate(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_iocg_forgive_debt($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void __probestub_iocost_iocg_forgive_debt(Ptr<?> __data, Ptr<ioc_gq> iocg,
      String path, Ptr<ioc_now> now, @Unsigned int usage_pct, @Unsigned long old_debt,
      @Unsigned long new_debt, @Unsigned long old_delay, @Unsigned long new_delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iocost_iocg_idle($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __probestub_iocost_iocg_idle(Ptr<?> __data, Ptr<ioc_gq> iocg, String path,
      Ptr<ioc_now> now, @Unsigned long last_period, @Unsigned long cur_period,
      @Unsigned long vtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_add_to_ioend(Ptr<?> __data, Ptr<inode> inode,
      @Unsigned long pos, @Unsigned int dirty_len, Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_dio_complete(Ptr<?> __data, Ptr<kiocb> iocb, int error,
      @OriginalName("ssize_t") long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_dio_invalidate_fail(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_dio_rw_begin(Ptr<?> __data, Ptr<kiocb> iocb,
      Ptr<iov_iter> iter, @Unsigned int dio_flags, @Unsigned long done_before) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_dio_rw_queued(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_invalidate_folio(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_iomap_iter($arg1, $arg2, (const void *)$arg3, $arg4)")
  public static void __probestub_iomap_iter(Ptr<?> __data, Ptr<iomap_iter> iter, Ptr<?> ops,
      @Unsigned long caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_iter_dstmap(Ptr<?> __data, Ptr<inode> inode,
      Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_iter_srcmap(Ptr<?> __data, Ptr<inode> inode,
      Ptr<iomap> iomap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_readahead(Ptr<?> __data, Ptr<inode> inode, int nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_readpage(Ptr<?> __data, Ptr<inode> inode, int nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_release_folio(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_iomap_writeback_folio(Ptr<?> __data, Ptr<inode> inode,
      @OriginalName("loff_t") long off, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ipi_send_cpu($arg1, (const unsigned int)$arg2, $arg3, $arg4)")
  public static void __probestub_ipi_send_cpu(Ptr<?> __data, @Unsigned int cpu,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ipi_send_cpumask($arg1, (const struct cpumask *)$arg2, $arg3, $arg4)")
  public static void __probestub_ipi_send_cpumask(Ptr<?> __data, Ptr<cpumask> cpumask,
      @Unsigned long callsite, Ptr<?> callback) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_handler_entry(Ptr<?> __data, int irq, Ptr<irqaction> action) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_handler_exit(Ptr<?> __data, int irq, Ptr<irqaction> action,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_alloc(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_alloc_managed(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_assign(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_assign_system(Ptr<?> __data, int bit,
      Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_free(Ptr<?> __data, int bit, @Unsigned int cpu,
      Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_offline(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_online(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_remove_managed(Ptr<?> __data, int bit,
      @Unsigned int cpu, Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_remove_reserved(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_reserve(Ptr<?> __data, Ptr<irq_matrix> matrix) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_matrix_reserve_managed(Ptr<?> __data, int bit,
      @Unsigned int cpu, Ptr<irq_matrix> matrix, Ptr<cpumap> cmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_irq_noise($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static void __probestub_irq_noise(Ptr<?> __data, int vector, String desc,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_work_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_irq_work_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_itimer_expire(Ptr<?> __data, int which, Ptr<pid> pid,
      @Unsigned long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_itimer_state($arg1, $arg2, (const const struct itimerspec64*)$arg3, $arg4)")
  public static void __probestub_itimer_state(Ptr<?> __data, int which, Ptr<itimerspec64> value,
      @Unsigned long expires) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_checkpoint(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_checkpoint_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_chp_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_commit_flushing(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_commit_locking(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_commit_logging(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_drop_transaction(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_end_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_handle_extend(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int buffer_credits, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_handle_restart(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_handle_start(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int requested_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_handle_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned int type, @Unsigned int line_no, int interval, int sync, int requested_blocks,
      int dirtied_blocks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_lock_buffer_stall(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned long stall_ms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_run_stats(Ptr<?> __data,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("tid_t") int tid,
      Ptr<transaction_run_stats_s> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_shrink_checkpoint_list(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned @OriginalName("tid_t") int tid,
      @Unsigned @OriginalName("tid_t") int last_tid, @Unsigned long nr_freed,
      @Unsigned @OriginalName("tid_t") int next_tid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_shrink_count(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_shrink_scan_enter(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_shrink_scan_exit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal, @Unsigned long nr_to_scan,
      @Unsigned long nr_shrunk, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_start_commit(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      Ptr<@OriginalName("transaction_t") transaction_s> commit_transaction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_submit_inode_data(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_update_log_tail(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("tid_t") int first_tid, @Unsigned long block_nr,
      @Unsigned long freed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_jbd2_write_superblock(Ptr<?> __data,
      Ptr<@OriginalName("journal_t") journal_s> journal,
      @Unsigned @OriginalName("blk_opf_t") int write_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_kfree($arg1, $arg2, (const void *)$arg3)")
  public static void __probestub_kfree(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_kfree_skb(Ptr<?> __data, Ptr<sk_buff> skb, Ptr<?> location,
      skb_drop_reason reason, Ptr<sock> rx_sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_kmalloc($arg1, $arg2, (const void *)$arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __probestub_kmalloc(Ptr<?> __data, @Unsigned long call_site, Ptr<?> ptr,
      @Unsigned long bytes_req, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_kmem_cache_alloc($arg1, $arg2, (const void *)$arg3, $arg4, $arg5, $arg6)")
  public static void __probestub_kmem_cache_alloc(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s, @Unsigned @OriginalName("gfp_t") int gfp_flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_kmem_cache_free($arg1, $arg2, (const void *)$arg3, (const struct kmem_cache *)$arg4)")
  public static void __probestub_kmem_cache_free(Ptr<?> __data, @Unsigned long call_site,
      Ptr<?> ptr, Ptr<kmem_cache> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_advisor(Ptr<?> __data, long scan_time,
      @Unsigned long pages_to_scan, @Unsigned int cpu_percent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_enter(Ptr<?> __data, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_exit(Ptr<?> __data, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_merge_one_page(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_merge_with_ksm_page(Ptr<?> __data, Ptr<?> ksm_page,
      @Unsigned long pfn, Ptr<?> rmap_item, Ptr<?> mm, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_remove_ksm_page(Ptr<?> __data, @Unsigned long pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_remove_rmap_item(Ptr<?> __data, @Unsigned long pfn,
      Ptr<?> rmap_item, Ptr<?> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_start_scan(Ptr<?> __data, int seq,
      @Unsigned int rmap_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_ksm_stop_scan(Ptr<?> __data, int seq, @Unsigned int rmap_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_leases_conflict(Ptr<?> __data, boolean conflict,
      Ptr<file_lease> lease, Ptr<file_lease> breaker) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_local_timer_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_local_timer_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_locks_get_lock_context(Ptr<?> __data, Ptr<inode> inode, int type,
      Ptr<file_lock_context> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_locks_remove_posix(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lock> fl, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ma_op($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_ma_op(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ma_read($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_ma_read(Ptr<?> __data, String fn, Ptr<ma_state> mas) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_ma_write($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_ma_write(Ptr<?> __data, String fn, Ptr<ma_state> mas,
      @Unsigned long piv, Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_map(Ptr<?> __data, @Unsigned long iova,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mark_victim(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned @OriginalName("uid_t") int uid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_mc_event($arg1, (const unsigned int)$arg2, (const u8 *)$arg3, (const u8 *)$arg4, (const int)$arg5, (const u8)$arg6, (const s8)$arg7, (const s8)$arg8, (const s8)$arg9, $arg10, (const u8)$arg11, $arg12, (const u8 *)$arg13)")
  public static void __probestub_mc_event(Ptr<?> __data, @Unsigned int err_type, String error_msg,
      String label, int error_count, char mc_index, @OriginalName("s8") byte top_layer,
      @OriginalName("s8") byte mid_layer, @OriginalName("s8") byte low_layer,
      @Unsigned long address, char grain_bits, @Unsigned long syndrome, String driver_detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mce_record(Ptr<?> __data, Ptr<mce_hw_err> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_mctp_key_acquire($arg1, (const struct mctp_sk_key *)$arg2)")
  public static void __probestub_mctp_key_acquire(Ptr<?> __data, Ptr<mctp_sk_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_mctp_key_release($arg1, (const struct mctp_sk_key *)$arg2, $arg3)")
  public static void __probestub_mctp_key_release(Ptr<?> __data, Ptr<mctp_sk_key> key, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mdio_access(Ptr<?> __data, Ptr<mii_bus> bus, char read, char addr,
      @Unsigned int regnum, @Unsigned short val, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_mem_connect($arg1, (const struct xdp_mem_allocator *)$arg2, (const struct xdp_rxq_info *)$arg3)")
  public static void __probestub_mem_connect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa,
      Ptr<xdp_rxq_info> rxq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_mem_disconnect($arg1, (const struct xdp_mem_allocator *)$arg2)")
  public static void __probestub_mem_disconnect(Ptr<?> __data, Ptr<xdp_mem_allocator> xa) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_memcg_flush_stats(Ptr<?> __data, Ptr<mem_cgroup> memcg,
      long stats_updates, boolean force, boolean needs_flush) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_memory_failure_event(Ptr<?> __data, @Unsigned long pfn, int type,
      int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_calculate_totalreserve_pages(Ptr<?> __data,
      @Unsigned long totalreserve_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_collapse_huge_page(Ptr<?> __data, Ptr<mm_struct> mm,
      int isolated, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_collapse_huge_page_isolate(Ptr<?> __data, Ptr<folio> folio,
      int none_or_zero, int referenced, boolean writable, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_collapse_huge_page_swapin(Ptr<?> __data, Ptr<mm_struct> mm,
      int swapped_in, int referenced, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_begin(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_defer_compaction(Ptr<?> __data, Ptr<zone> zone,
      int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_defer_reset(Ptr<?> __data, Ptr<zone> zone,
      int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_deferred(Ptr<?> __data, Ptr<zone> zone, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_end(Ptr<?> __data, Ptr<compact_control> cc,
      @Unsigned long zone_start, @Unsigned long zone_end, boolean sync, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_fast_isolate_freepages(Ptr<?> __data,
      @Unsigned long start_pfn, @Unsigned long end_pfn, @Unsigned long nr_scanned,
      @Unsigned long nr_taken) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_finished(Ptr<?> __data, Ptr<zone> zone, int order,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_isolate_freepages(Ptr<?> __data,
      @Unsigned long start_pfn, @Unsigned long end_pfn, @Unsigned long nr_scanned,
      @Unsigned long nr_taken) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_isolate_migratepages(Ptr<?> __data,
      @Unsigned long start_pfn, @Unsigned long end_pfn, @Unsigned long nr_scanned,
      @Unsigned long nr_taken) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_kcompactd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_kcompactd_wake(Ptr<?> __data, int nid, int order,
      zone_type highest_zoneidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_migratepages(Ptr<?> __data,
      @Unsigned int nr_migratepages, @Unsigned int nr_succeeded) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_suitable(Ptr<?> __data, Ptr<zone> zone, int order,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_try_to_compact_pages(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, int prio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_compaction_wakeup_kcompactd(Ptr<?> __data, int nid, int order,
      zone_type highest_zoneidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_filemap_add_to_page_cache(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_filemap_delete_from_page_cache(Ptr<?> __data,
      Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_filemap_fault(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned long index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_filemap_get_pages(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned long index, @Unsigned long last_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_filemap_map_pages(Ptr<?> __data, Ptr<address_space> mapping,
      @Unsigned long index, @Unsigned long last_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_khugepaged_collapse_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> new_folio, @Unsigned long index, @Unsigned long addr, boolean is_shmem,
      Ptr<file> file, int nr, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_khugepaged_scan_file(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, Ptr<file> file, int present, int swap, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_khugepaged_scan_pmd(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<folio> folio, boolean writable, int referenced, int none_or_zero, int status,
      int unmapped) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_lru_activate(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_lru_insertion(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_migrate_pages(Ptr<?> __data, @Unsigned long succeeded,
      @Unsigned long failed, @Unsigned long thp_succeeded, @Unsigned long thp_failed,
      @Unsigned long thp_split, @Unsigned long large_folio_split, migrate_mode mode, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_migrate_pages_start(Ptr<?> __data, migrate_mode mode,
      int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_alloc(Ptr<?> __data, Ptr<page> page, @Unsigned int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_alloc_extfrag(Ptr<?> __data, Ptr<page> page,
      int alloc_order, int fallback_order, int alloc_migratetype, int fallback_migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_alloc_zone_locked(Ptr<?> __data, Ptr<page> page,
      @Unsigned int order, int migratetype, int percpu_refill) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_free(Ptr<?> __data, Ptr<page> page, @Unsigned int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_free_batched(Ptr<?> __data, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_page_pcpu_drain(Ptr<?> __data, Ptr<page> page,
      @Unsigned int order, int migratetype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_setup_per_zone_lowmem_reserve(Ptr<?> __data, Ptr<zone> zone,
      Ptr<zone> upper_zone, long lowmem_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_setup_per_zone_wmarks(Ptr<?> __data, Ptr<zone> zone) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_shrink_slab_end(Ptr<?> __data, Ptr<shrinker> shr, int nid,
      int shrinker_retval, long unused_scan_cnt, long new_scan_cnt, long total_scan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_shrink_slab_start(Ptr<?> __data, Ptr<shrinker> shr,
      Ptr<shrink_control> sc, long nr_objects_to_shrink, @Unsigned long cache_items,
      @Unsigned long delta, @Unsigned long total_scan, int priority) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_direct_reclaim_begin(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_direct_reclaim_end(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_kswapd_sleep(Ptr<?> __data, int nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_kswapd_wake(Ptr<?> __data, int nid, int zid, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_lru_isolate(Ptr<?> __data, int highest_zoneidx,
      int order, @Unsigned long nr_requested, @Unsigned long nr_scanned, @Unsigned long nr_skipped,
      @Unsigned long nr_taken, int lru) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_lru_shrink_active(Ptr<?> __data, int nid,
      @Unsigned long nr_taken, @Unsigned long nr_active, @Unsigned long nr_deactivated,
      @Unsigned long nr_referenced, int priority, int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_lru_shrink_inactive(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat, int priority,
      int file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_memcg_reclaim_begin(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_memcg_reclaim_end(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_memcg_softlimit_reclaim_begin(Ptr<?> __data, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_memcg_softlimit_reclaim_end(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_node_reclaim_begin(Ptr<?> __data, int nid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_node_reclaim_end(Ptr<?> __data,
      @Unsigned long nr_reclaimed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_reclaim_pages(Ptr<?> __data, int nid,
      @Unsigned long nr_scanned, @Unsigned long nr_reclaimed, Ptr<reclaim_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_throttled(Ptr<?> __data, int nid, int usec_timeout,
      int usec_delayed, int reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_wakeup_kswapd(Ptr<?> __data, int nid, int zid, int order,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mm_vmscan_write_folio(Ptr<?> __data, Ptr<folio> folio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mmap_lock_acquire_returned(Ptr<?> __data, Ptr<mm_struct> mm,
      boolean write, boolean success) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mmap_lock_released(Ptr<?> __data, Ptr<mm_struct> mm,
      boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mmap_lock_start_locking(Ptr<?> __data, Ptr<mm_struct> mm,
      boolean write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mmc_request_done(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mmc_request_start(Ptr<?> __data, Ptr<mmc_host> host,
      Ptr<mmc_request> mrq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mod_memcg_lruvec_state(Ptr<?> __data, Ptr<mem_cgroup> memcg,
      int item, int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mod_memcg_state(Ptr<?> __data, Ptr<mem_cgroup> memcg, int item,
      int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_module_free(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_module_get(Ptr<?> __data, Ptr<module> mod, @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_module_load(Ptr<?> __data, Ptr<module> mod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_module_put(Ptr<?> __data, Ptr<module> mod, @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_module_request(Ptr<?> __data, String name, boolean wait,
      @Unsigned long ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mon_llc_occupancy_limbo(Ptr<?> __data, @Unsigned int ctrl_hw_id,
      @Unsigned int mon_hw_id, int domain_id, @Unsigned long llc_occupancy_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mptcp_sendmsg_frag(Ptr<?> __data, Ptr<mptcp_ext> mpext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_mptcp_subflow_get_send(Ptr<?> __data,
      Ptr<mptcp_subflow_context> subflow) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_napi_gro_frags_entry($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_napi_gro_frags_entry(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_napi_gro_frags_exit(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_napi_gro_receive_entry($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_napi_gro_receive_entry(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_napi_gro_receive_exit(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_napi_poll(Ptr<?> __data, Ptr<napi_struct> napi, int work,
      int budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_neigh_cleanup_and_release(Ptr<?> __data, Ptr<neighbour> neigh,
      int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_neigh_create($arg1, $arg2, $arg3, (const void *)$arg4, (const struct neighbour *)$arg5, $arg6)")
  public static void __probestub_neigh_create(Ptr<?> __data, Ptr<neigh_table> tbl,
      Ptr<net_device> dev, Ptr<?> pkey, Ptr<neighbour> n, boolean exempt_from_gc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_neigh_event_send_dead(Ptr<?> __data, Ptr<neighbour> neigh,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_neigh_event_send_done(Ptr<?> __data, Ptr<neighbour> neigh,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_neigh_timer_handler(Ptr<?> __data, Ptr<neighbour> neigh, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_neigh_update($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6)")
  public static void __probestub_neigh_update(Ptr<?> __data, Ptr<neighbour> n,
      Ptr<java.lang.Character> lladdr, char _new, @Unsigned int flags, @Unsigned int nlmsg_pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_neigh_update_done(Ptr<?> __data, Ptr<neighbour> neigh, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_net_dev_queue(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_net_dev_start_xmit($arg1, (const struct sk_buff *)$arg2, (const struct net_device *)$arg3)")
  public static void __probestub_net_dev_start_xmit(Ptr<?> __data, Ptr<sk_buff> skb,
      Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_net_dev_xmit(Ptr<?> __data, Ptr<sk_buff> skb, int rc,
      Ptr<net_device> dev, @Unsigned int skb_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_net_dev_xmit_timeout(Ptr<?> __data, Ptr<net_device> dev,
      int queue_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_netif_receive_skb(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_netif_receive_skb_entry($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_netif_receive_skb_entry(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_netif_receive_skb_exit(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_netif_receive_skb_list_entry($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_netif_receive_skb_list_entry(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_netif_receive_skb_list_exit(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_netif_rx(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_netif_rx_entry($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_netif_rx_entry(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_netif_rx_exit(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_netlink_extack($arg1, (const u8 *)$arg2)")
  public static void __probestub_netlink_extack(Ptr<?> __data, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_nmi_handler(Ptr<?> __data, Ptr<?> handler, long delta_ns,
      int handled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_nmi_noise(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_non_standard_event($arg1, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg2, (const struct {\n"
          + "  u8 b[16];\n"
          + "} *)$arg3, (const u8 *)$arg4, (const u8)$arg5, (const u8 *)$arg6, (const unsigned int)$arg7)")
  public static void __probestub_non_standard_event(Ptr<?> __data,
      Ptr<@OriginalName("guid_t") uuid_t> sec_type, Ptr<@OriginalName("guid_t") uuid_t> fru_id,
      String fru_text, char sev, Ptr<java.lang.Character> err, @Unsigned int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_notifier_register(Ptr<?> __data, Ptr<?> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_notifier_run(Ptr<?> __data, Ptr<?> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_notifier_unregister(Ptr<?> __data, Ptr<?> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_oom_score_adj_update(Ptr<?> __data, Ptr<task_struct> task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_osnoise_sample(Ptr<?> __data, Ptr<osnoise_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_page_fault_kernel(Ptr<?> __data, @Unsigned long address,
      Ptr<pt_regs> regs, @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_page_fault_user(Ptr<?> __data, @Unsigned long address,
      Ptr<pt_regs> regs, @Unsigned long error_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_page_pool_release($arg1, (const struct page_pool *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_page_pool_release(Ptr<?> __data, Ptr<page_pool> pool, int inflight,
      @Unsigned int hold, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_page_pool_state_hold($arg1, (const struct page_pool *)$arg2, $arg3, $arg4)")
  public static void __probestub_page_pool_state_hold(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int hold) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_page_pool_state_release($arg1, (const struct page_pool *)$arg2, $arg3, $arg4)")
  public static void __probestub_page_pool_state_release(Ptr<?> __data, Ptr<page_pool> pool,
      @Unsigned @OriginalName("netmem_ref") long netmem, @Unsigned int release) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_page_pool_update_nid($arg1, (const struct page_pool *)$arg2, $arg3)")
  public static void __probestub_page_pool_update_nid(Ptr<?> __data, Ptr<page_pool> pool,
      int new_nid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_cfs_tp(Ptr<?> __data, Ptr<cfs_rq> cfs_rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_dl_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_hw_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_irq_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_rt_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pelt_se_tp(Ptr<?> __data, Ptr<sched_entity> se) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_percpu_alloc_percpu(Ptr<?> __data, @Unsigned long call_site,
      boolean reserved, boolean is_atomic, @Unsigned long size, @Unsigned long align,
      Ptr<?> base_addr, int off, Ptr<?> ptr, @Unsigned long bytes_alloc,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_percpu_alloc_percpu_fail(Ptr<?> __data, boolean reserved,
      boolean is_atomic, @Unsigned long size, @Unsigned long align) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_percpu_create_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_percpu_destroy_chunk(Ptr<?> __data, Ptr<?> base_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_percpu_free_percpu(Ptr<?> __data, Ptr<?> base_addr, int off,
      Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pm_qos_add_request(Ptr<?> __data, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pm_qos_remove_request(Ptr<?> __data, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pm_qos_update_flags(Ptr<?> __data, pm_qos_req_action action,
      int prev_value, int curr_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pm_qos_update_request(Ptr<?> __data, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pm_qos_update_target(Ptr<?> __data, pm_qos_req_action action,
      int prev_value, int curr_value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_posix_lock_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lock> fl, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_prq_report(Ptr<?> __data, Ptr<intel_iommu> iommu, Ptr<device> dev,
      @Unsigned long dw0, @Unsigned long dw1, @Unsigned long dw2, @Unsigned long dw3,
      @Unsigned long seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pseudo_lock_l2(Ptr<?> __data, @Unsigned long l2_hits,
      @Unsigned long l2_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pseudo_lock_l3(Ptr<?> __data, @Unsigned long l3_hits,
      @Unsigned long l3_miss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pseudo_lock_mem_latency(Ptr<?> __data, @Unsigned int latency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pstate_sample(Ptr<?> __data, @Unsigned int core_busy,
      @Unsigned int scaled_busy, @Unsigned int from, @Unsigned int to, @Unsigned long mperf,
      @Unsigned long aperf, @Unsigned long tsc, @Unsigned int freq, @Unsigned int io_boost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_purge_vmap_area_lazy(Ptr<?> __data, @Unsigned long start,
      @Unsigned long end, @Unsigned int npurged) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_pwm_apply($arg1, $arg2, (const struct pwm_state *)$arg3, $arg4)")
  public static void __probestub_pwm_apply(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<pwm_state> state,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_pwm_get($arg1, $arg2, (const struct pwm_state *)$arg3, $arg4)")
  public static void __probestub_pwm_get(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<pwm_state> state,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_pwm_read_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_pwm_round_waveform_fromhw($arg1, $arg2, (const void *)$arg3, $arg4, $arg5)")
  public static void __probestub_pwm_round_waveform_fromhw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<?> wfhw, Ptr<pwm_waveform> wf, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_pwm_round_waveform_tohw($arg1, $arg2, (const struct pwm_waveform *)$arg3, $arg4, $arg5)")
  public static void __probestub_pwm_round_waveform_tohw(Ptr<?> __data, Ptr<pwm_device> pwm,
      Ptr<pwm_waveform> wf, Ptr<?> wfhw, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_pwm_write_waveform($arg1, $arg2, (const void *)$arg3, $arg4)")
  public static void __probestub_pwm_write_waveform(Ptr<?> __data, Ptr<pwm_device> pwm, Ptr<?> wfhw,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_qdisc_create($arg1, (const struct Qdisc_ops *)$arg2, $arg3, $arg4)")
  public static void __probestub_qdisc_create(Ptr<?> __data, Ptr<Qdisc_ops> ops,
      Ptr<net_device> dev, @Unsigned int parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_qdisc_dequeue($arg1, $arg2, (const struct netdev_queue *)$arg3, $arg4, $arg5)")
  public static void __probestub_qdisc_dequeue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, int packets, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_qdisc_destroy(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_qdisc_enqueue($arg1, $arg2, (const struct netdev_queue *)$arg3, $arg4)")
  public static void __probestub_qdisc_enqueue(Ptr<?> __data, Ptr<Qdisc> qdisc,
      Ptr<netdev_queue> txq, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_qdisc_reset(Ptr<?> __data, Ptr<Qdisc> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_qi_submit(Ptr<?> __data, Ptr<intel_iommu> iommu,
      @Unsigned long qw0, @Unsigned long qw1, @Unsigned long qw2, @Unsigned long qw3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_rcu_stall_warning($arg1, (const u8 *)$arg2, (const u8 *)$arg3)")
  public static void __probestub_rcu_stall_warning(Ptr<?> __data, String rcuname, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_rcu_utilization($arg1, (const u8 *)$arg2)")
  public static void __probestub_rcu_utilization(Ptr<?> __data, String s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rdpmc(Ptr<?> __data, @Unsigned int msr, @Unsigned long val,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_read_msr(Ptr<?> __data, @Unsigned int msr, @Unsigned long val,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_reclaim_retry_zone(Ptr<?> __data, Ptr<zoneref> zoneref, int order,
      @Unsigned long reclaimable, @Unsigned long available, @Unsigned long min_wmark,
      int no_progress_loops, boolean wmark_check) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regcache_drop_region(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int from, @Unsigned int to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regcache_sync($arg1, $arg2, (const u8 *)$arg3, (const u8 *)$arg4)")
  public static void __probestub_regcache_sync(Ptr<?> __data, Ptr<regmap> map, String type,
      String status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_async_complete_done(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_async_complete_start(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_async_io_complete(Ptr<?> __data, Ptr<regmap> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_async_write_start(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regmap_bulk_read($arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static void __probestub_regmap_bulk_read(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regmap_bulk_write($arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static void __probestub_regmap_bulk_write(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, Ptr<?> val, int val_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_cache_bypass(Ptr<?> __data, Ptr<regmap> map, boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_cache_only(Ptr<?> __data, Ptr<regmap> map, boolean flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_hw_read_done(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_hw_read_start(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_hw_write_done(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_hw_write_start(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_reg_read(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_reg_read_cache(Ptr<?> __data, Ptr<regmap> map,
      @Unsigned int reg, @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_regmap_reg_write(Ptr<?> __data, Ptr<regmap> map, @Unsigned int reg,
      @Unsigned int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_bypass_disable($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_bypass_disable(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_bypass_disable_complete($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_bypass_disable_complete(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_bypass_enable($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_bypass_enable(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_bypass_enable_complete($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_bypass_enable_complete(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_disable($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_disable(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_disable_complete($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_disable_complete(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_enable($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_enable(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_enable_complete($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_enable_complete(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_enable_delay($arg1, (const u8 *)$arg2)")
  public static void __probestub_regulator_enable_delay(Ptr<?> __data, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_set_voltage($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_regulator_set_voltage(Ptr<?> __data, String name, int min,
      int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_regulator_set_voltage_complete($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_regulator_set_voltage_complete(Ptr<?> __data, String name,
      @Unsigned int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_remove_device_from_group(Ptr<?> __data, int group_id,
      Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_remove_migration_pmd(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_remove_migration_pte(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pte, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_reschedule_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_reschedule_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_idle(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_resume(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_return_int(Ptr<?> __data, Ptr<device> dev, @Unsigned long ip,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_status(Ptr<?> __data, Ptr<device> dev, rpm_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_suspend(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rpm_usage(Ptr<?> __data, Ptr<device> dev, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rseq_ip_fixup(Ptr<?> __data, @Unsigned long regs_ip,
      @Unsigned long start_ip, @Unsigned long post_commit_offset, @Unsigned long abort_ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rseq_update(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rss_stat(Ptr<?> __data, Ptr<mm_struct> mm, int member) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_alarm_irq_enable(Ptr<?> __data, @Unsigned int enabled,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_irq_set_freq(Ptr<?> __data, int freq, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_irq_set_state(Ptr<?> __data, int enabled, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_read_alarm(Ptr<?> __data, @OriginalName("time64_t") long secs,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_read_offset(Ptr<?> __data, long offset, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_read_time(Ptr<?> __data, @OriginalName("time64_t") long secs,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_set_alarm(Ptr<?> __data, @OriginalName("time64_t") long secs,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_set_offset(Ptr<?> __data, long offset, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_set_time(Ptr<?> __data, @OriginalName("time64_t") long secs,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_timer_dequeue(Ptr<?> __data, Ptr<rtc_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_timer_enqueue(Ptr<?> __data, Ptr<rtc_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rtc_timer_fired(Ptr<?> __data, Ptr<rtc_timer> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_rv_retries_error(Ptr<?> __data, String name, String event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sample_threshold(Ptr<?> __data, @Unsigned long start,
      @Unsigned long duration, @Unsigned long interference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sb_clear_inode_writeback(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sb_mark_inode_writeback(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_compute_energy_tp(Ptr<?> __data, Ptr<task_struct> p,
      int dst_cpu, @Unsigned long energy, @Unsigned long max_util, @Unsigned long busy_time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_cpu_capacity_tp(Ptr<?> __data, Ptr<rq> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_entry_tp(Ptr<?> __data, boolean preempt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_exit_tp(Ptr<?> __data, boolean is_switch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_sched_ext_dump($arg1, (const u8 *)$arg2)")
  public static void __probestub_sched_ext_dump(Ptr<?> __data, String line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_sched_ext_event($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_sched_ext_event(Ptr<?> __data, String name, long delta) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_kthread_stop(Ptr<?> __data, Ptr<task_struct> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_kthread_stop_ret(Ptr<?> __data, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_kthread_work_execute_end(Ptr<?> __data,
      Ptr<kthread_work> work, @OriginalName("kthread_work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_kthread_work_execute_start(Ptr<?> __data,
      Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_kthread_work_queue_work(Ptr<?> __data,
      Ptr<kthread_worker> worker, Ptr<kthread_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_migrate_task(Ptr<?> __data, Ptr<task_struct> p,
      int dest_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_move_numa(Ptr<?> __data, Ptr<task_struct> tsk, int src_cpu,
      int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_overutilized_tp(Ptr<?> __data, Ptr<root_domain> rd,
      boolean overutilized) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_pi_setprio(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<task_struct> pi_task) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_prepare_exec(Ptr<?> __data, Ptr<task_struct> task,
      Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_exec(Ptr<?> __data, Ptr<task_struct> p,
      @OriginalName("pid_t") int old_pid, Ptr<linux_binprm> bprm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_exit(Ptr<?> __data, Ptr<task_struct> p,
      boolean group_dead) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_fork(Ptr<?> __data, Ptr<task_struct> parent,
      Ptr<task_struct> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_free(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_hang(Ptr<?> __data, Ptr<task_struct> tsk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_process_wait(Ptr<?> __data, Ptr<pid> pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_set_need_resched_tp(Ptr<?> __data, Ptr<task_struct> tsk,
      int cpu, int tif) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_set_state_tp(Ptr<?> __data, Ptr<task_struct> tsk,
      int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_skip_cpuset_numa(Ptr<?> __data, Ptr<task_struct> tsk,
      Ptr<nodemask_t> mem_allowed_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_skip_vma_numa(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<vm_area_struct> vma, numa_vmaskip_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stat_blocked(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stat_iowait(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stat_runtime(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long runtime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stat_sleep(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stat_wait(Ptr<?> __data, Ptr<task_struct> tsk,
      @Unsigned long delay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_stick_numa(Ptr<?> __data, Ptr<task_struct> src_tsk,
      int src_cpu, Ptr<task_struct> dst_tsk, int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_swap_numa(Ptr<?> __data, Ptr<task_struct> src_tsk,
      int src_cpu, Ptr<task_struct> dst_tsk, int dst_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_switch(Ptr<?> __data, boolean preempt, Ptr<task_struct> prev,
      Ptr<task_struct> next, @Unsigned int prev_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_update_nr_running_tp(Ptr<?> __data, Ptr<rq> rq, int change) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_util_est_cfs_tp(Ptr<?> __data, Ptr<cfs_rq> cfs_rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_util_est_se_tp(Ptr<?> __data, Ptr<sched_entity> se) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_wait_task(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_wake_idle_without_ipi(Ptr<?> __data, int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_wakeup(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_wakeup_new(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sched_waking(Ptr<?> __data, Ptr<task_struct> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_dispatch_cmd_done(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_dispatch_cmd_error(Ptr<?> __data, Ptr<scsi_cmnd> cmd,
      int rtn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_dispatch_cmd_start(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_dispatch_cmd_timeout(Ptr<?> __data, Ptr<scsi_cmnd> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_eh_wakeup(Ptr<?> __data, Ptr<Scsi_Host> shost) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_prepare_zone_append(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long lba, @Unsigned int wp_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_scsi_zone_wp_update(Ptr<?> __data, Ptr<scsi_cmnd> cmnd,
      @Unsigned @OriginalName("sector_t") long rq_sector, @Unsigned int wp_offset,
      @Unsigned int good_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_selinux_audited($arg1, $arg2, $arg3, $arg4, (const u8 *)$arg5)")
  public static void __probestub_selinux_audited(Ptr<?> __data, Ptr<selinux_audit_data> sad,
      String scontext, String tcontext, String tclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_set_migration_pmd(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_set_migration_pte(Ptr<?> __data, @Unsigned long addr,
      @Unsigned long pte, int order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_signal_deliver(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<k_sigaction> ka) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_signal_generate(Ptr<?> __data, int sig, Ptr<kernel_siginfo> info,
      Ptr<task_struct> task, int group, int result) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_sk_data_ready($arg1, (const struct sock *)$arg2)")
  public static void __probestub_sk_data_ready(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_skb_copy_datagram_iovec($arg1, (const struct sk_buff *)$arg2, $arg3)")
  public static void __probestub_skb_copy_datagram_iovec(Ptr<?> __data, Ptr<sk_buff> skb, int len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_skip_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_smbus_read($arg1, (const struct i2c_adapter *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static void __probestub_smbus_read(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_smbus_reply($arg1, (const struct i2c_adapter *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data *)$arg8, $arg9)")
  public static void __probestub_smbus_reply(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data, int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_smbus_result($arg1, (const struct i2c_adapter *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_smbus_result(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      int res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_smbus_write($arg1, (const struct i2c_adapter *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union i2c_smbus_data *)$arg8)")
  public static void __probestub_smbus_write(Ptr<?> __data, Ptr<i2c_adapter> adap,
      @Unsigned short addr, @Unsigned short flags, char read_write, char command, int protocol,
      Ptr<i2c_smbus_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sock_exceed_buf_limit(Ptr<?> __data, Ptr<sock> sk, Ptr<proto> prot,
      long allocated, int kind) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sock_rcvqueue_full(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sock_recv_length(Ptr<?> __data, Ptr<sock> sk, int ret, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sock_send_length(Ptr<?> __data, Ptr<sock> sk, int ret, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_softirq_entry(Ptr<?> __data, @Unsigned int vec_nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_softirq_exit(Ptr<?> __data, @Unsigned int vec_nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_softirq_noise(Ptr<?> __data, int vector, @Unsigned long start,
      @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_softirq_raise(Ptr<?> __data, @Unsigned int vec_nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_controller_busy(Ptr<?> __data,
      Ptr<spi_controller> controller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_controller_idle(Ptr<?> __data,
      Ptr<spi_controller> controller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_message_done(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_message_start(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_message_submit(Ptr<?> __data, Ptr<spi_message> msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_set_cs(Ptr<?> __data, Ptr<spi_device> spi, boolean enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_setup(Ptr<?> __data, Ptr<spi_device> spi, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_transfer_start(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spi_transfer_stop(Ptr<?> __data, Ptr<spi_message> msg,
      Ptr<spi_transfer> xfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spurious_apic_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_spurious_apic_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_start_task_reaping(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_subflow_check_data_avail(Ptr<?> __data, char status,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_suspend_resume($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void __probestub_suspend_resume(Ptr<?> __data, String action, int val,
      boolean start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_swiotlb_bounced(Ptr<?> __data, Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dev_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sync_timeline(Ptr<?> __data, Ptr<sync_timeline> timeline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sys_enter(Ptr<?> __data, Ptr<pt_regs> regs, long id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_sys_exit(Ptr<?> __data, Ptr<pt_regs> regs, long ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_task_newtask(Ptr<?> __data, Ptr<task_struct> task,
      @Unsigned long clone_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_task_prctl_unknown(Ptr<?> __data, int option, @Unsigned long arg2,
      @Unsigned long arg3, @Unsigned long arg4, @Unsigned long arg5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_task_rename($arg1, $arg2, (const u8 *)$arg3)")
  public static void __probestub_task_rename(Ptr<?> __data, Ptr<task_struct> task, String comm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tasklet_entry(Ptr<?> __data, Ptr<tasklet_struct> t, Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tasklet_exit(Ptr<?> __data, Ptr<tasklet_struct> t, Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_handshake_failure($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __probestub_tcp_ao_handshake_failure(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb, char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_key_not_found($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __probestub_tcp_ao_key_not_found(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_mismatch($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __probestub_tcp_ao_mismatch(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_rcv_sne_update($arg1, (const struct sock *)$arg2, $arg3)")
  public static void __probestub_tcp_ao_rcv_sne_update(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_rnext_request($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __probestub_tcp_ao_rnext_request(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_snd_sne_update($arg1, (const struct sock *)$arg2, $arg3)")
  public static void __probestub_tcp_ao_snd_sne_update(Ptr<?> __data, Ptr<sock> sk,
      @Unsigned int new_sne) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_synack_no_key($arg1, (const struct sock *)$arg2, (const u8)$arg3, (const u8)$arg4)")
  public static void __probestub_tcp_ao_synack_no_key(Ptr<?> __data, Ptr<sock> sk, char keyid,
      char rnext) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_ao_wrong_maclen($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const u8)$arg4, (const u8)$arg5, (const u8)$arg6)")
  public static void __probestub_tcp_ao_wrong_maclen(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      char keyid, char rnext, char maclen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_bad_csum($arg1, (const struct sk_buff *)$arg2)")
  public static void __probestub_tcp_bad_csum(Ptr<?> __data, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_cong_state_set($arg1, $arg2, (const u8)$arg3)")
  public static void __probestub_tcp_cong_state_set(Ptr<?> __data, Ptr<sock> sk, char ca_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_cwnd_reduction_tp($arg1, (const struct sock *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_tcp_cwnd_reduction_tp(Ptr<?> __data, Ptr<sock> sk,
      int newly_acked_sacked, int newly_lost, int flag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tcp_destroy_sock(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_hash_ao_required($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_hash_ao_required(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_hash_bad_header($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_hash_bad_header(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_hash_md5_mismatch($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_hash_md5_mismatch(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_hash_md5_required($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_hash_md5_required(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_hash_md5_unexpected($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_hash_md5_unexpected(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_probe($arg1, $arg2, (const struct sk_buff *)$arg3)")
  public static void __probestub_tcp_probe(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tcp_rcv_space_adjust(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tcp_rcvbuf_grow(Ptr<?> __data, Ptr<sock> sk, int time) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tcp_receive_reset(Ptr<?> __data, Ptr<sock> sk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_retransmit_skb($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, $arg4)")
  public static void __probestub_tcp_retransmit_skb(Ptr<?> __data, Ptr<sock> sk, Ptr<sk_buff> skb,
      int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_retransmit_synack($arg1, (const struct sock *)$arg2, (const struct request_sock *)$arg3)")
  public static void __probestub_tcp_retransmit_synack(Ptr<?> __data, Ptr<sock> sk,
      Ptr<request_sock> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_send_reset($arg1, (const struct sock *)$arg2, (const struct sk_buff *)$arg3, (const enum sk_rst_reason)$arg4)")
  public static void __probestub_tcp_send_reset(Ptr<?> __data, Ptr<sock> sk,
      Ptr<sk_buff> skb__nullable, sk_rst_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tcp_sendmsg_locked($arg1, (const struct sock *)$arg2, (const struct msghdr *)$arg3, (const struct sk_buff *)$arg4, $arg5)")
  public static void __probestub_tcp_sendmsg_locked(Ptr<?> __data, Ptr<sock> sk, Ptr<msghdr> msg,
      Ptr<sk_buff> skb, int size_goal) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_test_pages_isolated(Ptr<?> __data, @Unsigned long start_pfn,
      @Unsigned long end_pfn, @Unsigned long fin_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_apic_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_apic_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_power_actor(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int actor_id, @Unsigned int req_power, @Unsigned int granted_power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_power_allocator(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      @Unsigned int total_req_power, @Unsigned int total_granted_power, int num_actors,
      @Unsigned int power_range, @Unsigned int max_allocatable_power, int current_temp,
      int delta_temp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_power_allocator_pid(Ptr<?> __data,
      Ptr<thermal_zone_device> tz, int err, int err_integral, long p, long i, long d, int output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_power_devfreq_get_power(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, Ptr<devfreq_dev_status> status, @Unsigned long freq,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_power_devfreq_limit(Ptr<?> __data,
      Ptr<thermal_cooling_device> cdev, @Unsigned long freq, @Unsigned long cdev_state,
      @Unsigned int power) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_temperature(Ptr<?> __data, Ptr<thermal_zone_device> tz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thermal_zone_trip(Ptr<?> __data, Ptr<thermal_zone_device> tz,
      int trip, thermal_trip_type trip_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_thread_noise(Ptr<?> __data, Ptr<task_struct> t,
      @Unsigned long start, @Unsigned long duration) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_threshold_apic_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_threshold_apic_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tick_stop(Ptr<?> __data, int success, int dependency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_time_out_leases(Ptr<?> __data, Ptr<inode> inode,
      Ptr<file_lease> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_base_idle(Ptr<?> __data, boolean is_idle,
      @Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_cancel(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_expire_entry(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long baseclk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_expire_exit(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_init(Ptr<?> __data, Ptr<timer_list> timer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timer_start(Ptr<?> __data, Ptr<timer_list> timer,
      @Unsigned long bucket_expiry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_timerlat_sample(Ptr<?> __data, Ptr<timerlat_sample> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tlb_flush(Ptr<?> __data, int reason, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tls_alert_recv($arg1, (const struct sock *)$arg2, $arg3, $arg4)")
  public static void __probestub_tls_alert_recv(Ptr<?> __data, Ptr<sock> sk, char level,
      char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tls_alert_send($arg1, (const struct sock *)$arg2, $arg3, $arg4)")
  public static void __probestub_tls_alert_send(Ptr<?> __data, Ptr<sock> sk, char level,
      char description) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tls_contenttype($arg1, (const struct sock *)$arg2, $arg3)")
  public static void __probestub_tls_contenttype(Ptr<?> __data, Ptr<sock> sk, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_connect_child_parent(Ptr<?> __data, Ptr<tmigr_group> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_connect_cpu_parent(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_active(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_idle(Ptr<?> __data, Ptr<tmigr_cpu> tmc,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_new_timer(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_new_timer_idle(Ptr<?> __data, Ptr<tmigr_cpu> tmc,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_offline(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_cpu_online(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_group_set(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_group_set_cpu_active(Ptr<?> __data, Ptr<tmigr_group> group,
      tmigr_state state, @Unsigned int childmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_group_set_cpu_inactive(Ptr<?> __data, Ptr<tmigr_group> group,
      tmigr_state state, @Unsigned int childmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_handle_remote(Ptr<?> __data, Ptr<tmigr_group> group) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_handle_remote_cpu(Ptr<?> __data, Ptr<tmigr_cpu> tmc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_tmigr_update_events(Ptr<?> __data, Ptr<tmigr_group> child,
      Ptr<tmigr_group> group, tmigr_state childstate, tmigr_state groupstate,
      @Unsigned long nextevt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_track_foreign_dirty(Ptr<?> __data, Ptr<folio> folio,
      Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tsm_mr_read($arg1, (const struct tsm_measurement_register *)$arg2)")
  public static void __probestub_tsm_mr_read(Ptr<?> __data, Ptr<tsm_measurement_register> mr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tsm_mr_refresh($arg1, (const struct tsm_measurement_register *)$arg2, $arg3)")
  public static void __probestub_tsm_mr_refresh(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      int rc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_tsm_mr_write($arg1, (const struct tsm_measurement_register *)$arg2, (const u8 *)$arg3)")
  public static void __probestub_tsm_mr_write(Ptr<?> __data, Ptr<tsm_measurement_register> mr,
      Ptr<java.lang.Character> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_udp_fail_queue_rcv_skb(Ptr<?> __data, int rc, Ptr<sock> sk,
      Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_unmap(Ptr<?> __data, @Unsigned long iova, @Unsigned long size,
      @Unsigned long unmapped_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_user_enter(Ptr<?> __data, int dummy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_user_exit(Ptr<?> __data, int dummy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_activate(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean can_reserve, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_alloc(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, boolean reserved, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_alloc_managed(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_clear(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, @Unsigned int cpu, @Unsigned int prev_vector, @Unsigned int prev_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_config(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, @Unsigned int cpu, @Unsigned int apicdest) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_deactivate(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean can_reserve, boolean reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_free_moved(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int cpu, @Unsigned int vector, boolean is_managed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_reserve(Ptr<?> __data, @Unsigned int irq, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_reserve_managed(Ptr<?> __data, @Unsigned int irq, int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_setup(Ptr<?> __data, @Unsigned int irq, boolean is_legacy,
      int ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_teardown(Ptr<?> __data, @Unsigned int irq,
      boolean is_managed, boolean has_reserved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vector_update(Ptr<?> __data, @Unsigned int irq,
      @Unsigned int vector, @Unsigned int cpu, @Unsigned int prev_vector, @Unsigned int prev_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_vm_unmapped_area(Ptr<?> __data, @Unsigned long addr,
      Ptr<vm_unmapped_area_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_wake_reaper(Ptr<?> __data, int pid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_wakeup_source_activate($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_wakeup_source_activate(Ptr<?> __data, String name,
      @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_wakeup_source_deactivate($arg1, (const u8 *)$arg2, $arg3)")
  public static void __probestub_wakeup_source_deactivate(Ptr<?> __data, String name,
      @Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_watchdog_ping(Ptr<?> __data, Ptr<watchdog_device> wdd, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_watchdog_set_timeout(Ptr<?> __data, Ptr<watchdog_device> wdd,
      @Unsigned int timeout, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_watchdog_start(Ptr<?> __data, Ptr<watchdog_device> wdd, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_watchdog_stop(Ptr<?> __data, Ptr<watchdog_device> wdd, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_wbc_writepage(Ptr<?> __data, Ptr<writeback_control> wbc,
      Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_wbt_lat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned long lat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_wbt_stat(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_wbt_step($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_wbt_step(Ptr<?> __data, Ptr<backing_dev_info> bdi, String msg,
      int step, @Unsigned long window, @Unsigned int bg, @Unsigned int normal, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_wbt_timer(Ptr<?> __data, Ptr<backing_dev_info> bdi,
      @Unsigned int status, int step, @Unsigned int inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_workqueue_activate_work(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_workqueue_execute_end(Ptr<?> __data, Ptr<work_struct> work,
      @OriginalName("work_func_t") Ptr<?> function) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_workqueue_execute_start(Ptr<?> __data, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_workqueue_queue_work(Ptr<?> __data, int req_cpu,
      Ptr<pool_workqueue> pwq, Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_write_msr(Ptr<?> __data, @Unsigned int msr, @Unsigned long val,
      int failed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_bdi_register(Ptr<?> __data, Ptr<backing_dev_info> bdi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_dirty_folio(Ptr<?> __data, Ptr<folio> folio,
      Ptr<address_space> mapping) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_dirty_inode(Ptr<?> __data, Ptr<inode> inode, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_dirty_inode_enqueue(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_dirty_inode_start(Ptr<?> __data, Ptr<inode> inode,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_exec(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_lazytime(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_lazytime_iput(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_mark_inode_dirty(Ptr<?> __data, Ptr<inode> inode,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_pages_written(Ptr<?> __data, long pages_written) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_queue(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_queue_io(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work, @Unsigned long dirtied_before, int moved) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_sb_inodes_requeue(Ptr<?> __data, Ptr<inode> inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_single_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_single_inode_start(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc, @Unsigned long nr_to_write) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_start(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_wait(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_wake_background(Ptr<?> __data, Ptr<bdi_writeback> wb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_write_inode(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_write_inode_start(Ptr<?> __data, Ptr<inode> inode,
      Ptr<writeback_control> wbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_writeback_written(Ptr<?> __data, Ptr<bdi_writeback> wb,
      Ptr<wb_writeback_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_after_save(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_before_save(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_copy_dst(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_dropped(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_regs_activated(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_regs_deactivated(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_fpu_xstate_check_failed(Ptr<?> __data, Ptr<fpu> fpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_platform_ipi_entry(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_x86_platform_ipi_exit(Ptr<?> __data, int vector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xdp_bulk_tx($arg1, (const struct net_device *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_xdp_bulk_tx(Ptr<?> __data, Ptr<net_device> dev, int sent,
      int drops, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xdp_cpumap_enqueue(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int to_cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xdp_cpumap_kthread(Ptr<?> __data, int map_id,
      @Unsigned int processed, @Unsigned int drops, int sched, Ptr<xdp_cpumap_stats> xdp_stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xdp_devmap_xmit($arg1, (const struct net_device *)$arg2, (const struct net_device *)$arg3, $arg4, $arg5, $arg6)")
  public static void __probestub_xdp_devmap_xmit(Ptr<?> __data, Ptr<net_device> from_dev,
      Ptr<net_device> to_dev, int sent, int drops, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xdp_exception($arg1, (const struct net_device *)$arg2, (const struct bpf_prog *)$arg3, $arg4)")
  public static void __probestub_xdp_exception(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<bpf_prog> xdp, @Unsigned int act) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xdp_redirect($arg1, (const struct net_device *)$arg2, (const struct bpf_prog *)$arg3, (const void *)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_xdp_redirect(Ptr<?> __data, Ptr<net_device> dev, Ptr<bpf_prog> xdp,
      Ptr<?> tgt, int err, bpf_map_type map_type, @Unsigned int map_id, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xdp_redirect_err($arg1, (const struct net_device *)$arg2, (const struct bpf_prog *)$arg3, (const void *)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void __probestub_xdp_redirect_err(Ptr<?> __data, Ptr<net_device> dev,
      Ptr<bpf_prog> xdp, Ptr<?> tgt, int err, bpf_map_type map_type, @Unsigned int map_id,
      @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xen_cpu_load_idt($arg1, (const struct desc_ptr *)$arg2)")
  public static void __probestub_xen_cpu_load_idt(Ptr<?> __data, Ptr<desc_ptr> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xen_cpu_set_ldt($arg1, (const void *)$arg2, $arg3)")
  public static void __probestub_xen_cpu_set_ldt(Ptr<?> __data, Ptr<?> addr,
      @Unsigned int entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xen_cpu_write_gdt_entry($arg1, $arg2, $arg3, (const void *)$arg4, $arg5)")
  public static void __probestub_xen_cpu_write_gdt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, Ptr<?> desc, int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xen_cpu_write_idt_entry($arg1, $arg2, $arg3, (const gate_struct *)$arg4)")
  public static void __probestub_xen_cpu_write_idt_entry(Ptr<?> __data,
      Ptr<@OriginalName("gate_desc") gate_struct> dt, int entrynum,
      Ptr<@OriginalName("gate_desc") gate_struct> ent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_cpu_write_ldt_entry(Ptr<?> __data, Ptr<desc_struct> dt,
      int entrynum, @Unsigned long desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_batch(Ptr<?> __data, xen_lazy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_callback(Ptr<?> __data,
      @OriginalName("xen_mc_callback_fn_t") Ptr<?> fn, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_entry(Ptr<?> __data, Ptr<multicall_entry> mc,
      @Unsigned int nargs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_entry_alloc(Ptr<?> __data, @Unsigned long args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_extend_args(Ptr<?> __data, @Unsigned long op,
      @Unsigned long args, xen_mc_extend_args res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_flush(Ptr<?> __data, @Unsigned int mcidx,
      @Unsigned int argidx, @Unsigned int cbidx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_flush_reason(Ptr<?> __data, xen_mc_flush_reason reason) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mc_issue(Ptr<?> __data, xen_lazy_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_alloc_ptpage(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long pfn, @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__probestub_xen_mmu_flush_tlb_multi($arg1, (const struct cpumask *)$arg2, $arg3, $arg4, $arg5)")
  public static void __probestub_xen_mmu_flush_tlb_multi(Ptr<?> __data, Ptr<cpumask> cpus,
      Ptr<mm_struct> mm, @Unsigned long addr, @Unsigned long end) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_flush_tlb_one_user(Ptr<?> __data, @Unsigned long addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_pgd_pin(Ptr<?> __data, Ptr<mm_struct> mm, Ptr<pgd_t> pgd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_pgd_unpin(Ptr<?> __data, Ptr<mm_struct> mm,
      Ptr<pgd_t> pgd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_ptep_modify_prot_commit(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long addr, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_ptep_modify_prot_start(Ptr<?> __data, Ptr<mm_struct> mm,
      @Unsigned long addr, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_release_ptpage(Ptr<?> __data, @Unsigned long pfn,
      @Unsigned int level, boolean pinned) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_set_p4d(Ptr<?> __data, Ptr<p4d_t> p4dp,
      Ptr<p4d_t> user_p4dp, p4d_t p4dval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_set_pmd(Ptr<?> __data, Ptr<pmd_t> pmdp, pmd_t pmdval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_set_pte(Ptr<?> __data, Ptr<pte_t> ptep, pte_t pteval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_set_pud(Ptr<?> __data, Ptr<pud_t> pudp, pud_t pudval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xen_mmu_write_cr3(Ptr<?> __data, boolean kernel,
      @Unsigned long cr3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_add_endpoint(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_address_ctrl_ctx(Ptr<?> __data,
      Ptr<xhci_input_control_ctx> ctrl_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_address_ctx(Ptr<?> __data, Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx, @Unsigned int ep_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_alloc_dev(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_alloc_stream_info_ctx(Ptr<?> __data,
      Ptr<xhci_stream_info> info, @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_alloc_virt_device(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_configure_endpoint(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_configure_endpoint_ctrl_ctx(Ptr<?> __data,
      Ptr<xhci_input_control_ctx> ctrl_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_alloc_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_free_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_gadget_ep_queue(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_giveback_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_handle_event(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_handle_transfer(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbc_queue_request(Ptr<?> __data, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_address(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_cancel_urb(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_context_change(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_init(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_quirks(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_reset_ep(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_dbg_ring_expansion(Ptr<?> __data, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_discover_or_reset_device(Ptr<?> __data,
      Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_free_dev(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_free_virt_device(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_get_port_status(Ptr<?> __data, Ptr<xhci_port> port,
      @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_addr_dev(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_config_ep(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_disable_slot(Ptr<?> __data,
      Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_reset_dev(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_reset_ep(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_set_deq(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_set_deq_ep(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_set_deq_stream(Ptr<?> __data,
      Ptr<xhci_stream_info> info, @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_cmd_stop_ep(Ptr<?> __data, Ptr<xhci_ep_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_command(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_event(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_port_status(Ptr<?> __data, Ptr<xhci_port> port,
      @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_handle_transfer(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_hub_status_data(Ptr<?> __data, Ptr<xhci_port> port,
      @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_inc_deq(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_inc_enq(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_queue_trb(Ptr<?> __data, Ptr<xhci_ring> ring,
      Ptr<xhci_generic_trb> trb, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_ring_alloc(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_ring_ep_doorbell(Ptr<?> __data, @Unsigned int slot,
      @Unsigned int doorbell) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_ring_expansion(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_ring_free(Ptr<?> __data, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_ring_host_doorbell(Ptr<?> __data, @Unsigned int slot,
      @Unsigned int doorbell) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_setup_addressable_virt_device(Ptr<?> __data,
      Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_setup_device(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_setup_device_slot(Ptr<?> __data, Ptr<xhci_slot_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_stop_device(Ptr<?> __data, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_urb_dequeue(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_urb_enqueue(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __probestub_xhci_urb_giveback(Ptr<?> __data, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }
}
